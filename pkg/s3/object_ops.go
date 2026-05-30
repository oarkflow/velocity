package s3

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type RangeSpec struct {
	Start int64
	End   int64
}

type CopyResult struct {
	ETag         string    `xml:"ETag"`
	LastModified time.Time `xml:"LastModified"`
}

func ParseRangeHeader(rangeHeader string, objectSize int64) ([]RangeSpec, error) {
	if rangeHeader == "" {
		return nil, nil
	}
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, fmt.Errorf("invalid range header")
	}
	rangeStr := strings.TrimPrefix(rangeHeader, "bytes=")
	var ranges []RangeSpec
	for _, part := range strings.Split(rangeStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		dashIdx := strings.IndexByte(part, '-')
		if dashIdx < 0 {
			return nil, fmt.Errorf("invalid range spec")
		}
		startStr := part[:dashIdx]
		endStr := part[dashIdx+1:]
		var r RangeSpec
		if startStr == "" {
			suffix, err := strconv.ParseInt(endStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid range suffix")
			}
			r.Start = objectSize - suffix
			if r.Start < 0 {
				r.Start = 0
			}
			r.End = objectSize - 1
		} else if endStr == "" {
			start, err := strconv.ParseInt(startStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid range start")
			}
			r.Start = start
			r.End = objectSize - 1
		} else {
			start, err := strconv.ParseInt(startStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid range start")
			}
			end, err := strconv.ParseInt(endStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid range end")
			}
			r.Start = start
			r.End = end
		}
		if r.Start > r.End || r.Start >= objectSize {
			return nil, fmt.Errorf("range not satisfiable")
		}
		if r.End >= objectSize {
			r.End = objectSize - 1
		}
		ranges = append(ranges, r)
	}
	return ranges, nil
}

func GetObjectRange(data []byte, rangeSpec RangeSpec) []byte {
	if rangeSpec.Start >= int64(len(data)) {
		return nil
	}
	end := rangeSpec.End + 1
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	return data[rangeSpec.Start:end]
}

func ComputeETag(data []byte) string {
	hash := md5.Sum(data)
	return fmt.Sprintf(`"%s"`, hex.EncodeToString(hash[:]))
}

func ComputeMultipartETag(partETags []string) string {
	combined := make([]byte, 0)
	for _, etag := range partETags {
		etag = strings.Trim(etag, `"`)
		hashBytes, _ := hex.DecodeString(etag)
		combined = append(combined, hashBytes...)
	}
	finalHash := md5.Sum(combined)
	return fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(finalHash[:]), len(partETags))
}

type ConditionalCheck struct {
	IfMatch           string
	IfNoneMatch       string
	IfModifiedSince   *time.Time
	IfUnmodifiedSince *time.Time
}

func EvaluateConditions(check ConditionalCheck, etag string, lastModified time.Time) (bool, int) {
	if check.IfMatch != "" {
		if check.IfMatch != "*" && check.IfMatch != etag {
			return false, 412
		}
	}
	if check.IfNoneMatch != "" {
		if check.IfNoneMatch == "*" || check.IfNoneMatch == etag {
			return false, 304
		}
	}
	if check.IfModifiedSince != nil {
		if !lastModified.After(*check.IfModifiedSince) {
			return false, 304
		}
	}
	if check.IfUnmodifiedSince != nil {
		if lastModified.After(*check.IfUnmodifiedSince) {
			return false, 412
		}
	}
	return true, 200
}
