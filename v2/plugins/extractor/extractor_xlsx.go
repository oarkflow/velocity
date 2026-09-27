package extractor

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/oarkflow/velocity/v2/api"
)

// --- XLSX (OOXML spreadsheet) ---
//
// A .xlsx file is a ZIP archive, same family as .docx: shared strings live
// in xl/sharedStrings.xml (a table of <si> entries, each either a plain
// <t> or a run-split <r><t>...</r> sequence), and each worksheet's cells
// live in xl/worksheets/sheetN.xml as <row>/<c> elements. A cell's t="s"
// attribute means its <v> is an INDEX into the shared-string table rather
// than a literal value — everything else (t="str", or no t at all, i.e.
// a plain number) is used as-is.
var sheetFileRe = regexp.MustCompile(`^xl/worksheets/sheet(\d+)\.xml$`)

func extractXLSX(content []byte) (api.ExtractedContent, error) {
	zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return api.ExtractedContent{}, fmt.Errorf("extractor/xlsx: not a valid zip/xlsx: %w", err)
	}

	var sharedStrings []string
	var sheetFiles []*zip.File
	for _, f := range zr.File {
		switch {
		case f.Name == "xl/sharedStrings.xml":
			sharedStrings, err = parseSharedStrings(f)
			if err != nil {
				return api.ExtractedContent{}, err
			}
		case sheetFileRe.MatchString(f.Name):
			sheetFiles = append(sheetFiles, f)
		}
	}
	if len(sheetFiles) == 0 {
		return api.ExtractedContent{}, fmt.Errorf("extractor/xlsx: no worksheets found")
	}
	sort.Slice(sheetFiles, func(i, j int) bool {
		return sheetNumber(sheetFiles[i].Name) < sheetNumber(sheetFiles[j].Name)
	})

	var sb strings.Builder
	totalRows := 0
	maxCols := 0
	for i, sf := range sheetFiles {
		rows, err := parseWorksheet(sf, sharedStrings)
		if err != nil {
			return api.ExtractedContent{}, err
		}
		if i > 0 {
			sb.WriteByte('\n')
		}
		for _, row := range rows {
			sb.WriteString(strings.Join(row, "\t"))
			sb.WriteByte('\n')
			if len(row) > maxCols {
				maxCols = len(row)
			}
		}
		totalRows += len(rows)
	}

	return api.ExtractedContent{
		Text: strings.TrimRight(sb.String(), "\n"),
		Metadata: map[string]any{
			"sheets":  len(sheetFiles),
			"rows":    totalRows,
			"columns": maxCols,
		},
	}, nil
}

func sheetNumber(name string) int {
	m := sheetFileRe.FindStringSubmatch(name)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// parseSharedStrings decodes xl/sharedStrings.xml into an ordered slice
// where index i is shared string i, matching how cells with t="s"
// reference it.
func parseSharedStrings(f *zip.File) ([]string, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("extractor/xlsx: sharedStrings: %w", err)
	}
	defer rc.Close()

	var strs []string
	var cur strings.Builder
	inSI := false
	dec := xml.NewDecoder(rc)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("extractor/xlsx: sharedStrings xml: %w", err)
		}
		switch se := tok.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "si":
				inSI = true
				cur.Reset()
			}
		case xml.EndElement:
			if se.Name.Local == "si" {
				strs = append(strs, cur.String())
				inSI = false
			}
		case xml.CharData:
			if inSI {
				cur.Write(se)
			}
		}
	}
	return strs, nil
}

// parseWorksheet decodes one xl/worksheets/sheetN.xml into rows of cell
// text, resolving shared-string references. Cell position is derived from
// the cell's "r" attribute (e.g. "B3" -> column index 1) so that sparse
// rows (cells omitted when empty, as real spreadsheet software emits)
// still land in the correct column rather than shifting left.
func parseWorksheet(f *zip.File, sharedStrings []string) ([][]string, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("extractor/xlsx: worksheet: %w", err)
	}
	defer rc.Close()

	var rows [][]string
	var curRow []string
	var curVal strings.Builder
	var curType string
	var curCol int
	inValue := false

	dec := xml.NewDecoder(rc)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("extractor/xlsx: worksheet xml: %w", err)
		}
		switch se := tok.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "row":
				curRow = nil
			case "c":
				curType = ""
				curCol = -1
				for _, a := range se.Attr {
					switch a.Name.Local {
					case "t":
						curType = a.Value
					case "r":
						curCol = columnFromRef(a.Value)
					}
				}
			case "v":
				inValue = true
				curVal.Reset()
			}
		case xml.EndElement:
			switch se.Name.Local {
			case "v":
				inValue = false
				val := curVal.String()
				if curType == "s" {
					if idx, err := strconv.Atoi(val); err == nil && idx >= 0 && idx < len(sharedStrings) {
						val = sharedStrings[idx]
					}
				}
				if curCol >= 0 {
					for len(curRow) <= curCol {
						curRow = append(curRow, "")
					}
					curRow[curCol] = val
				} else {
					curRow = append(curRow, val)
				}
			case "row":
				rows = append(rows, curRow)
			}
		case xml.CharData:
			if inValue {
				curVal.Write(se)
			}
		}
	}
	return rows, nil
}

// columnFromRef converts a cell reference like "B3" to a zero-based
// column index (A=0, B=1, ..., Z=25, AA=26, ...). Returns -1 if ref has
// no leading letters (malformed).
func columnFromRef(ref string) int {
	col := 0
	found := false
	for _, ch := range ref {
		switch {
		case ch >= 'A' && ch <= 'Z':
			found = true
			col = col*26 + int(ch-'A'+1)
		case ch >= 'a' && ch <= 'z':
			found = true
			col = col*26 + int(ch-'a'+1)
		default:
			if found {
				return col - 1
			}
			return -1
		}
	}
	if !found {
		return -1
	}
	return col - 1
}
