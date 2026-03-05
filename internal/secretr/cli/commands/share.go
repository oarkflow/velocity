package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity"
	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/files"
	"github.com/oarkflow/velocity/internal/secretr/core/share"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/pion/webrtc/v4"
	"github.com/urfave/cli/v3"
)

// Share commands

func ShareCreate(ctx context.Context, cmd *cli.Command) error {
	shareType := strings.ToLower(strings.TrimSpace(cmd.String("type")))
	resource := cmd.String("resource")
	recipient := cmd.String("recipient")
	expiresIn := cmd.Duration("expires-in")
	maxAccess := cmd.Int("max-access")
	oneTime := cmd.Bool("one-time")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeShareCreate); err != nil {
		return err
	}

	resourceType, resourceID, err := resolveShareResourceForCreate(ctx, c, shareType, resource)
	if err != nil {
		return err
	}

	recipientID := types.ID(recipient)
	var recipientPtr *types.ID
	var recipientPubKey []byte
	if strings.TrimSpace(recipient) != "" {
		recipientPtr = &recipientID
		identity, identityErr := c.Identity.GetIdentity(ctx, recipientID)
		if identityErr != nil {
			return fmt.Errorf("recipient identity not found: %w", identityErr)
		}
		recipientPubKey = identity.PublicKey
		if len(recipientPubKey) == 0 {
			if encPubStr, ok := identity.Metadata["encryption_public_key"].(string); ok && strings.TrimSpace(encPubStr) != "" {
				if decoded, decErr := base64.StdEncoding.DecodeString(encPubStr); decErr == nil {
					recipientPubKey = decoded
				}
			}
		}
	}

	shr, err := c.Share.CreateShare(ctx, share.CreateShareOptions{
		Type:            resourceType,
		ResourceID:      resourceID,
		RecipientID:     recipientPtr,
		RecipientPubKey: recipientPubKey,
		ExpiresIn:       expiresIn,
		MaxAccess:       maxAccess,
		CreatorID:       c.CurrentIdentityID(),
		OneTime:         oneTime,
	})
	if err != nil {
		return err
	}

	success("Share created: %s", shr.ID)
	return nil
}

func ShareList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	shares, err := c.Share.ListShares(ctx, share.ListSharesOptions{
		CreatorID: c.CurrentIdentityID(),
	})
	if err != nil {
		return err
	}
	return output(cmd, shares)
}

func ShareRevoke(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.Share.RevokeShare(ctx, types.ID(id), c.CurrentIdentityID()); err != nil {
		return err
	}
	success("Share revoked")
	return nil
}

func ShareAccept(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeShareAccept); err != nil {
		return err
	}
	access, err := c.Share.AccessShare(ctx, types.ID(id), c.CurrentIdentityID())
	if err != nil {
		return err
	}
	success("Share accepted: %s", access.ShareID)
	info("Resource: %s (%s)", access.ResourceID, access.Type)
	return nil
}

func ShareExport(ctx context.Context, cmd *cli.Command) error {
	id := types.ID(strings.TrimSpace(cmd.String("id")))
	outputPath := strings.TrimSpace(cmd.String("output"))

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeShareExport); err != nil {
		return err
	}

	shr, pkgID, exported, err := buildSharePackageForTransfer(ctx, c, id)
	if err != nil {
		return err
	}
	if shr.CreatorID != c.CurrentIdentityID() {
		return fmt.Errorf("only share creator can export this share")
	}

	if err := os.WriteFile(outputPath, exported, 0600); err != nil {
		return err
	}

	success("Share exported: %s (package_id=%s)", outputPath, pkgID)
	return nil
}

func ShareImport(ctx context.Context, cmd *cli.Command) error {
	inputPath := strings.TrimSpace(cmd.String("input"))
	outputPath := strings.TrimSpace(cmd.String("output"))
	password := cmd.String("password")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeShareAccept); err != nil {
		return err
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(password) == "" {
		password, err = promptPassword("Enter your password to import share: ")
		if err != nil {
			return err
		}
	}

	priv, err := c.Identity.GetEncryptionPrivateKey(ctx, c.CurrentIdentityID(), password)
	if err != nil {
		return fmt.Errorf("failed to load recipient decryption key: %w", err)
	}
	imported, err := c.Share.ImportOfflinePackage(ctx, data, priv)
	if err != nil {
		return err
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, imported.Data, 0600); err != nil {
			return err
		}
		success("Share imported: %s", imported.ShareID)
		info("Payload written to: %s", outputPath)
		return nil
	}

	fmt.Println(base64.StdEncoding.EncodeToString(imported.Data))
	success("Share imported: %s", imported.ShareID)
	info("Payload printed as base64; use --output to write raw bytes")
	return nil
}

func ShareQRGenerate(ctx context.Context, cmd *cli.Command) error {
	shareID := strings.TrimSpace(cmd.String("id"))
	output := strings.TrimSpace(cmd.String("output"))
	apiURL := strings.TrimSpace(cmd.String("api-url"))

	if shareID == "" {
		return fmt.Errorf("share id is required")
	}

	payload := fmt.Sprintf("secretr://share/%s", shareID)
	if apiURL != "" {
		payload = strings.TrimRight(apiURL, "/") + "/api/v1/shares/accept/" + shareID
	}

	if _, err := exec.LookPath("qrencode"); err != nil {
		fmt.Printf("QR payload: %s\n", payload)
		return fmt.Errorf("qrencode binary not found; install qrencode for image/terminal rendering")
	}
	if output != "" {
		if err := exec.Command("qrencode", "-o", output, payload).Run(); err != nil {
			return err
		}
		success("QR code generated: %s", output)
		return nil
	}
	qrOut, err := exec.Command("qrencode", "-t", "ANSIUTF8", payload).CombinedOutput()
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", string(qrOut))
	return nil
}

func ShareQRDecode(ctx context.Context, cmd *cli.Command) error {
	input := strings.TrimSpace(cmd.String("input"))
	if input == "" {
		return fmt.Errorf("input image path is required")
	}
	if _, err := exec.LookPath("zbarimg"); err != nil {
		return fmt.Errorf("zbarimg binary not found; install zbar for QR decode")
	}
	out, err := exec.Command("zbarimg", "--quiet", "--raw", input).CombinedOutput()
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", strings.TrimSpace(string(out)))
	return nil
}

func ShareLANSend(ctx context.Context, cmd *cli.Command) error {
	id := types.ID(strings.TrimSpace(cmd.String("id")))
	bindAddr := strings.TrimSpace(cmd.String("bind"))
	apiURL := strings.TrimSpace(cmd.String("api-url"))
	ttl := cmd.Duration("ttl")
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	showQR := cmd.Bool("qr")
	if bindAddr == "" {
		bindAddr = "0.0.0.0:8787"
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeShareExport); err != nil {
		return err
	}

	shr, pkgID, exported, err := buildSharePackageForTransfer(ctx, c, id)
	if err != nil {
		return err
	}
	if shr.CreatorID != c.CurrentIdentityID() {
		return fmt.Errorf("only share creator can LAN-send this share")
	}

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	baseURL := strings.TrimSpace(apiURL)
	if baseURL == "" {
		baseURL = "http://" + lanAdvertiseAddr(ln.Addr().String())
	}
	shareURL := strings.TrimRight(baseURL, "/") + "/package/" + string(pkgID)

	mux := http.NewServeMux()
	done := make(chan struct{})
	mux.HandleFunc("/package/"+string(pkgID), func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(exported)
		select {
		case <-done:
		default:
			close(done)
		}
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = srv.Serve(ln)
	}()

	success("LAN share ready")
	info("URL: %s", shareURL)
	info("TTL: %s", ttl.String())
	info("Package ID: %s", pkgID)
	if showQR {
		if _, lookErr := exec.LookPath("qrencode"); lookErr == nil {
			qrOut, qrErr := exec.Command("qrencode", "-t", "ANSIUTF8", shareURL).CombinedOutput()
			if qrErr == nil {
				fmt.Printf("%s\n", string(qrOut))
			}
		}
	}

	timer := time.NewTimer(ttl)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	case <-done:
	}
	_ = srv.Shutdown(context.Background())
	return nil
}

func ShareLANReceive(ctx context.Context, cmd *cli.Command) error {
	rawURL := strings.TrimSpace(cmd.String("url"))
	outputPath := strings.TrimSpace(cmd.String("output"))
	password := cmd.String("password")
	if rawURL == "" {
		return fmt.Errorf("url is required")
	}
	if strings.HasPrefix(rawURL, "secretr://") {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return fmt.Errorf("invalid url: %w", err)
		}
		rawURL = "https://" + strings.TrimPrefix(parsed.Host+parsed.Path, "/")
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeShareAccept); err != nil {
		return err
	}
	if strings.TrimSpace(password) == "" {
		password, err = promptPassword("Enter your password to import share: ")
		if err != nil {
			return err
		}
	}
	priv, err := c.Identity.GetEncryptionPrivateKey(ctx, c.CurrentIdentityID(), password)
	if err != nil {
		return fmt.Errorf("failed to load recipient decryption key: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("failed to fetch package: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	packageData, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return err
	}

	var js map[string]any
	if err := json.Unmarshal(packageData, &js); err != nil {
		return fmt.Errorf("invalid package payload from url: %w", err)
	}
	imported, err := c.Share.ImportOfflinePackage(ctx, packageData, priv)
	if err != nil {
		return err
	}
	if outputPath != "" {
		if err := os.WriteFile(outputPath, imported.Data, 0600); err != nil {
			return err
		}
		success("LAN share imported: %s", imported.ShareID)
		info("Payload written to: %s", outputPath)
		return nil
	}
	fmt.Println(base64.StdEncoding.EncodeToString(imported.Data))
	success("LAN share imported: %s", imported.ShareID)
	info("Payload printed as base64; use --output to write raw bytes")
	return nil
}

func ShareWebRTCOffer(ctx context.Context, cmd *cli.Command) error {
	id := types.ID(strings.TrimSpace(cmd.String("id")))
	shareType := strings.ToLower(strings.TrimSpace(cmd.String("type")))
	resource := strings.TrimSpace(cmd.String("resource"))
	recipient := strings.TrimSpace(cmd.String("recipient"))
	bindAddr := strings.TrimSpace(cmd.String("bind"))
	apiURL := strings.TrimSpace(cmd.String("api-url"))
	showQR := cmd.Bool("qr")
	ttl := cmd.Duration("ttl")
	timeout := cmd.Duration("timeout")
	stun := strings.TrimSpace(cmd.String("stun"))
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if bindAddr == "" {
		bindAddr = "0.0.0.0:8789"
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeShareExport); err != nil {
		return err
	}
	if id == "" {
		if shareType == "" || resource == "" || recipient == "" {
			return fmt.Errorf("provide --id or (--type, --resource, --recipient)")
		}
		if err := c.RequireScope(types.ScopeShareCreate); err != nil {
			return err
		}
		resourceType, resourceID, err := resolveShareResourceForCreate(ctx, c, shareType, resource)
		if err != nil {
			return err
		}
		recipientID := types.ID(recipient)
		identity, err := c.Identity.GetIdentity(ctx, recipientID)
		if err != nil {
			return fmt.Errorf("recipient identity not found: %w", err)
		}
		recipientPubKey := identity.PublicKey
		if len(recipientPubKey) == 0 {
			if encPubStr, ok := identity.Metadata["encryption_public_key"].(string); ok && strings.TrimSpace(encPubStr) != "" {
				if decoded, decErr := base64.StdEncoding.DecodeString(encPubStr); decErr == nil {
					recipientPubKey = decoded
				}
			}
		}
		if len(recipientPubKey) == 0 {
			return fmt.Errorf("recipient public key is required")
		}
		created, err := c.Share.CreateShare(ctx, share.CreateShareOptions{
			Type:            resourceType,
			ResourceID:      resourceID,
			CreatorID:       c.CurrentIdentityID(),
			RecipientID:     &recipientID,
			RecipientPubKey: recipientPubKey,
		})
		if err != nil {
			return err
		}
		id = created.ID
	}

	shr, pkgID, pkgBytes, err := buildSharePackageForTransfer(ctx, c, id)
	if err != nil {
		return err
	}
	if shr.CreatorID != c.CurrentIdentityID() {
		return fmt.Errorf("only share creator can perform webrtc-offer")
	}

	pc, err := newWebRTCPeer(stun)
	if err != nil {
		return err
	}
	defer pc.Close()

	ackCh := make(chan string, 1)
	errCh := make(chan error, 1)
	dc, err := pc.CreateDataChannel("secretr-share", nil)
	if err != nil {
		return err
	}
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if msg.IsString {
			var envelope shareWebRTCEnvelope
			if jsonErr := json.Unmarshal(msg.Data, &envelope); jsonErr == nil {
				switch envelope.Type {
				case "ack":
					ackCh <- envelope.ShareID
				case "err":
					errCh <- fmt.Errorf("receiver error: %s", envelope.Error)
				}
			}
		}
	})
	dc.OnOpen(func() {
		go func() {
			if sendErr := sendWebRTCPackage(dc, shr.ID, pkgID, pkgBytes); sendErr != nil {
				errCh <- sendErr
			}
		}()
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		return err
	}
	<-webrtc.GatheringCompletePromise(pc)
	local := pc.LocalDescription()
	if local == nil {
		return fmt.Errorf("failed to create local offer")
	}
	offerSignal := shareWebRTCSignal{Type: local.Type.String(), SDP: local.SDP, ShareID: string(shr.ID), PackageID: string(pkgID)}

	answerCh := make(chan shareWebRTCSignal, 1)
	token, err := randomTransferToken()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	mux := http.NewServeMux()
	basePath := "/webrtc/" + token
	mux.HandleFunc(basePath+"/offer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(offerSignal)
	})
	mux.HandleFunc(basePath+"/answer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var sig shareWebRTCSignal
		if err := json.NewDecoder(r.Body).Decode(&sig); err != nil {
			http.Error(w, "invalid answer", http.StatusBadRequest)
			return
		}
		if strings.ToLower(strings.TrimSpace(sig.Type)) != "answer" || strings.TrimSpace(sig.SDP) == "" {
			http.Error(w, "invalid answer", http.StatusBadRequest)
			return
		}
		select {
		case answerCh <- sig:
		default:
		}
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc(basePath+"/meta", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"share_id":    string(shr.ID),
			"package_id":  string(pkgID),
			"type":        shr.Type,
			"resource_id": string(shr.ResourceID),
		})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	baseURL := strings.TrimSpace(apiURL)
	if baseURL == "" {
		baseURL = "http://" + lanAdvertiseAddr(ln.Addr().String())
	}
	sessionURL := strings.TrimRight(baseURL, "/") + basePath
	success("WebRTC sender ready")
	info("Share: %s type=%s resource=%s", shr.ID, shr.Type, shr.ResourceID)
	info("Receiver URL: %s", sessionURL)
	if showQR {
		if _, lookErr := exec.LookPath("qrencode"); lookErr == nil {
			if qrOut, qrErr := exec.Command("qrencode", "-t", "ANSIUTF8", sessionURL).CombinedOutput(); qrErr == nil {
				fmt.Printf("%s\n", string(qrOut))
			}
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, minDuration(timeout, ttl))
	defer cancel()
	var answerSignal shareWebRTCSignal
	select {
	case answerSignal = <-answerCh:
	case <-waitCtx.Done():
		_ = srv.Shutdown(context.Background())
		return fmt.Errorf("timeout waiting for receiver answer")
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answerSignal.SDP,
	}); err != nil {
		_ = srv.Shutdown(context.Background())
		return err
	}

	select {
	case ack := <-ackCh:
		_ = srv.Shutdown(context.Background())
		success("WebRTC transfer completed (ack=%s)", ack)
		return nil
	case recvErr := <-errCh:
		_ = srv.Shutdown(context.Background())
		return recvErr
	case <-waitCtx.Done():
		_ = srv.Shutdown(context.Background())
		return fmt.Errorf("timeout waiting for receiver ack")
	}
}

func ShareWebRTCAnswer(ctx context.Context, cmd *cli.Command) error {
	sessionURL := strings.TrimRight(strings.TrimSpace(cmd.String("url")), "/")
	outputPath := strings.TrimSpace(cmd.String("output"))
	password := cmd.String("password")
	timeout := cmd.Duration("timeout")
	stun := strings.TrimSpace(cmd.String("stun"))
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if sessionURL == "" {
		return fmt.Errorf("url is required")
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeShareAccept); err != nil {
		return err
	}
	if strings.TrimSpace(password) == "" {
		password, err = promptPassword("Enter your password to import share: ")
		if err != nil {
			return err
		}
	}
	priv, err := c.Identity.GetEncryptionPrivateKey(ctx, c.CurrentIdentityID(), password)
	if err != nil {
		return fmt.Errorf("failed to load recipient decryption key: %w", err)
	}

	offerReq, err := http.NewRequestWithContext(ctx, http.MethodGet, sessionURL+"/offer", nil)
	if err != nil {
		return err
	}
	offerResp, err := http.DefaultClient.Do(offerReq)
	if err != nil {
		return err
	}
	defer offerResp.Body.Close()
	if offerResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(offerResp.Body, 4096))
		return fmt.Errorf("failed to fetch offer: status=%d body=%s", offerResp.StatusCode, strings.TrimSpace(string(body)))
	}
	var offerSignal shareWebRTCSignal
	if err := json.NewDecoder(offerResp.Body).Decode(&offerSignal); err != nil {
		return fmt.Errorf("invalid offer response: %w", err)
	}
	if strings.TrimSpace(offerSignal.SDP) == "" {
		return fmt.Errorf("offer sdp is empty")
	}
	if strings.ToLower(strings.TrimSpace(offerSignal.Type)) != "offer" {
		return fmt.Errorf("offer endpoint returned non-offer")
	}

	pc, err := newWebRTCPeer(stun)
	if err != nil {
		return err
	}
	defer pc.Close()

	doneCh := make(chan error, 1)
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		var mu sync.Mutex
		state := &shareWebRTCReceiveState{}
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			mu.Lock()
			defer mu.Unlock()
			if msg.IsString {
				var env shareWebRTCEnvelope
				if jsonErr := json.Unmarshal(msg.Data, &env); jsonErr == nil {
					switch env.Type {
					case "meta":
						state.ShareID = env.ShareID
						state.PackageID = env.PackageID
						state.ExpectedSize = env.Size
						state.ExpectedCRC = env.CRC32
					case "chunk":
						raw, decErr := base64.StdEncoding.DecodeString(env.Chunk)
						if decErr != nil {
							_ = dc.SendText(mustJSON(shareWebRTCEnvelope{Type: "err", Error: "invalid chunk encoding"}))
							doneCh <- decErr
							return
						}
						state.Payload = append(state.Payload, raw...)
					case "end":
						if state.ExpectedSize > 0 && len(state.Payload) != state.ExpectedSize {
							err := fmt.Errorf("payload size mismatch: got=%d want=%d", len(state.Payload), state.ExpectedSize)
							_ = dc.SendText(mustJSON(shareWebRTCEnvelope{Type: "err", Error: err.Error()}))
							doneCh <- err
							return
						}
						if state.ExpectedCRC != 0 && crc32.ChecksumIEEE(state.Payload) != state.ExpectedCRC {
							err := fmt.Errorf("payload crc mismatch")
							_ = dc.SendText(mustJSON(shareWebRTCEnvelope{Type: "err", Error: err.Error()}))
							doneCh <- err
							return
						}
						imported, impErr := c.Share.ImportOfflinePackage(ctx, state.Payload, priv)
						if impErr != nil {
							_ = dc.SendText(mustJSON(shareWebRTCEnvelope{Type: "err", Error: impErr.Error()}))
							doneCh <- impErr
							return
						}
						if outputPath != "" {
							if writeErr := os.WriteFile(outputPath, imported.Data, 0600); writeErr != nil {
								_ = dc.SendText(mustJSON(shareWebRTCEnvelope{Type: "err", Error: writeErr.Error()}))
								doneCh <- writeErr
								return
							}
						} else {
							fmt.Println(base64.StdEncoding.EncodeToString(imported.Data))
						}
						_ = dc.SendText(mustJSON(shareWebRTCEnvelope{Type: "ack", ShareID: string(imported.ShareID)}))
						doneCh <- nil
					}
				}
			}
		})
	})

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  offerSignal.SDP,
	}); err != nil {
		return err
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return err
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		return err
	}
	<-webrtc.GatheringCompletePromise(pc)
	local := pc.LocalDescription()
	if local == nil {
		return fmt.Errorf("failed to create local answer")
	}
	answerBody, _ := json.Marshal(shareWebRTCSignal{Type: local.Type.String(), SDP: local.SDP})
	answerReq, err := http.NewRequestWithContext(ctx, http.MethodPost, sessionURL+"/answer", bytes.NewReader(answerBody))
	if err != nil {
		return err
	}
	answerReq.Header.Set("Content-Type", "application/json")
	answerResp, err := http.DefaultClient.Do(answerReq)
	if err != nil {
		return err
	}
	answerResp.Body.Close()
	if answerResp.StatusCode/100 != 2 {
		return fmt.Errorf("sender rejected answer: %s", answerResp.Status)
	}
	info("Answer sent; waiting for package over data channel")

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case recvErr := <-doneCh:
		if recvErr != nil {
			return recvErr
		}
		success("WebRTC share received and imported")
		if outputPath != "" {
			info("Payload written to: %s", outputPath)
		} else {
			info("Payload printed as base64; use --output to write raw bytes")
		}
		return nil
	case <-waitCtx.Done():
		return fmt.Errorf("timeout waiting for incoming package")
	}
}

func lanAdvertiseAddr(listenAddr string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if err != nil {
		return listenAddr
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		return net.JoinHostPort(host, port)
	}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			return net.JoinHostPort(ip4.String(), port)
		}
	}
	return net.JoinHostPort("127.0.0.1", port)
}

type shareWebRTCSignal struct {
	Type      string `json:"type"`
	SDP       string `json:"sdp"`
	ShareID   string `json:"share_id,omitempty"`
	PackageID string `json:"package_id,omitempty"`
}

type shareWebRTCEnvelope struct {
	Type      string `json:"type"`
	ShareID   string `json:"share_id,omitempty"`
	PackageID string `json:"package_id,omitempty"`
	Size      int    `json:"size,omitempty"`
	CRC32     uint32 `json:"crc32,omitempty"`
	Chunk     string `json:"chunk,omitempty"`
	Error     string `json:"error,omitempty"`
}

type shareWebRTCReceiveState struct {
	ShareID      string
	PackageID    string
	ExpectedSize int
	ExpectedCRC  uint32
	Payload      []byte
}

func newWebRTCPeer(stun string) (*webrtc.PeerConnection, error) {
	if strings.TrimSpace(stun) == "" {
		stun = "stun:stun.l.google.com:19302"
	}
	return webrtc.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{{URLs: []string{stun}}},
	})
}

func sendWebRTCPackage(dc *webrtc.DataChannel, shareID, packageID types.ID, packageData []byte) error {
	meta := shareWebRTCEnvelope{
		Type:      "meta",
		ShareID:   string(shareID),
		PackageID: string(packageID),
		Size:      len(packageData),
		CRC32:     crc32.ChecksumIEEE(packageData),
	}
	if err := dc.SendText(mustJSON(meta)); err != nil {
		return err
	}
	const chunkSize = 12 * 1024
	for i := 0; i < len(packageData); i += chunkSize {
		end := i + chunkSize
		if end > len(packageData) {
			end = len(packageData)
		}
		chunk := base64.StdEncoding.EncodeToString(packageData[i:end])
		if err := dc.SendText(mustJSON(shareWebRTCEnvelope{Type: "chunk", Chunk: chunk})); err != nil {
			return err
		}
	}
	return dc.SendText(mustJSON(shareWebRTCEnvelope{Type: "end"}))
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func writeWebRTCSignalFile(path string, signal shareWebRTCSignal) error {
	b, err := json.MarshalIndent(signal, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func waitAndReadSignal(ctx context.Context, path string) (shareWebRTCSignal, error) {
	var lastErr error
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		b, err := os.ReadFile(path)
		if err == nil {
			var sig shareWebRTCSignal
			if jerr := json.Unmarshal(b, &sig); jerr != nil {
				lastErr = jerr
			} else if strings.TrimSpace(sig.SDP) == "" {
				lastErr = fmt.Errorf("signal sdp is empty")
			} else {
				return sig, nil
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return shareWebRTCSignal{}, fmt.Errorf("failed waiting for signal %s: %w", path, lastErr)
			}
			return shareWebRTCSignal{}, fmt.Errorf("timeout waiting for signal %s", path)
		case <-ticker.C:
		}
	}
}

func randomTransferToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func buildSharePackageForTransfer(ctx context.Context, c *client.Client, id types.ID) (*types.Share, types.ID, []byte, error) {
	shr, err := c.Share.GetShare(ctx, id)
	if err != nil {
		return nil, "", nil, err
	}
	if shr.CreatorID != c.CurrentIdentityID() {
		return nil, "", nil, fmt.Errorf("only share creator can transfer this share")
	}
	recipientPubKey := shr.RecipientKey
	if len(recipientPubKey) == 0 && shr.RecipientID != nil {
		identity, identityErr := c.Identity.GetIdentity(ctx, *shr.RecipientID)
		if identityErr != nil {
			return nil, "", nil, fmt.Errorf("could not resolve recipient public key: %w", identityErr)
		}
		recipientPubKey = identity.PublicKey
		if len(recipientPubKey) == 0 {
			if encPubStr, ok := identity.Metadata["encryption_public_key"].(string); ok && strings.TrimSpace(encPubStr) != "" {
				if decoded, decErr := base64.StdEncoding.DecodeString(encPubStr); decErr == nil {
					recipientPubKey = decoded
				}
			}
		}
	}
	if len(recipientPubKey) == 0 {
		return nil, "", nil, fmt.Errorf("recipient public key is required")
	}
	resourceData, err := resolveShareResourceData(ctx, c, shr)
	if err != nil {
		return nil, "", nil, err
	}
	pkg, err := c.Share.CreateOfflinePackage(ctx, share.OfflinePackageOptions{
		ShareID:         shr.ID,
		ResourceData:    resourceData,
		RecipientPubKey: recipientPubKey,
	})
	if err != nil {
		return nil, "", nil, err
	}
	exported, err := c.Share.ExportOfflinePackage(ctx, pkg.ID)
	if err != nil {
		return nil, "", nil, err
	}
	return shr, pkg.ID, exported, nil
}

func resolveShareResourceData(ctx context.Context, c *client.Client, shr *types.Share) ([]byte, error) {
	typ := strings.ToLower(strings.TrimSpace(shr.Type))
	switch typ {
	case "secret":
		if v, found, err := getVelocitySecretValue(string(shr.ResourceID)); err != nil {
			return nil, fmt.Errorf("failed to resolve shared secret payload: %w", err)
		} else if found {
			return []byte(v), nil
		}
		mfaVerified := false
		if sess := c.CurrentSession(); sess != nil {
			mfaVerified = sess.MFAVerified
		}
		val, err := c.Secrets.Get(ctx, string(shr.ResourceID), c.CurrentIdentityID(), mfaVerified)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve shared secret payload: %w", err)
		}
		return val, nil
	case "file", "object":
		if data, ok := getVelocityObjectData(c, string(shr.ResourceID)); ok {
			return data, nil
		}
		var buf bytes.Buffer
		err := c.Files.Download(ctx, string(shr.ResourceID), files.DownloadOptions{
			AccessorID:  c.CurrentIdentityID(),
			MFAVerified: c.CurrentSession() != nil && c.CurrentSession().MFAVerified,
		}, &buf)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve shared file payload: %w", err)
		}
		return buf.Bytes(), nil
	case "folder":
		db := velocityDB()
		if db == nil {
			return nil, fmt.Errorf("folder sharing requires velocity database")
		}
		data, err := buildFolderArchive(db, string(shr.ResourceID), string(c.CurrentIdentityID()))
		if err != nil {
			return nil, fmt.Errorf("failed to resolve shared folder payload: %w", err)
		}
		return data, nil
	case "envelope":
		data, err := os.ReadFile(string(shr.ResourceID))
		if err != nil {
			return nil, fmt.Errorf("failed to resolve shared envelope payload: %w", err)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported share type for export: %s", shr.Type)
	}
}

func resolveShareResourceForCreate(ctx context.Context, c *client.Client, shareType, resource string) (string, types.ID, error) {
	shareType = strings.ToLower(strings.TrimSpace(shareType))
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "", "", fmt.Errorf("resource is required")
	}
	switch shareType {
	case "secret":
		if _, found, err := getVelocitySecretValue(resource); err != nil {
			return "", "", fmt.Errorf("failed to validate secret resource %q: %w", resource, err)
		} else if found {
			return "secret", types.ID(resource), nil
		}
		mfaVerified := false
		if sess := c.CurrentSession(); sess != nil {
			mfaVerified = sess.MFAVerified
		}
		if _, err := c.Secrets.Get(ctx, resource, c.CurrentIdentityID(), mfaVerified); err != nil {
			return "", "", fmt.Errorf("secret resource not found or not accessible: %s", resource)
		}
		return "secret", types.ID(resource), nil
	case "file", "object":
		if ok := hasVelocityObject(resource); ok {
			return "object", types.ID(resource), nil
		}
		if _, err := c.Files.GetMetadata(ctx, resource); err != nil {
			return "", "", fmt.Errorf("file/object resource not found: %s", resource)
		}
		return "file", types.ID(resource), nil
	case "folder":
		db := velocityDB()
		if db == nil {
			return "", "", fmt.Errorf("folder sharing requires velocity database")
		}
		if _, err := db.GetFolder(resource); err != nil {
			return "", "", fmt.Errorf("folder resource not found: %s", resource)
		}
		return "folder", types.ID(resource), nil
	case "envelope":
		st, err := os.Stat(resource)
		if err != nil || st.IsDir() {
			return "", "", fmt.Errorf("envelope resource not found: %s", resource)
		}
		return "envelope", types.ID(resource), nil
	default:
		return "", "", fmt.Errorf("unsupported share type %q (expected: secret, file, folder, object, envelope)", shareType)
	}
}

func velocityDB() *velocity.DB {
	adapter := client.GetGlobalAdapter()
	if adapter == nil {
		return nil
	}
	return adapter.GetVelocityDB()
}

func hasVelocityObject(path string) bool {
	db := velocityDB()
	if db == nil {
		return false
	}
	_, err := db.GetObjectMetadata(path)
	return err == nil
}

func getVelocityObjectData(c *client.Client, path string) ([]byte, bool) {
	db := velocityDB()
	if db == nil {
		return nil, false
	}
	data, _, err := db.GetObject(path, string(c.CurrentIdentityID()))
	if err != nil {
		return nil, false
	}
	return data, true
}

func buildFolderArchive(db *velocity.DB, folderPath, user string) ([]byte, error) {
	objects, err := db.ListObjects(velocity.ObjectListOptions{
		Folder:    folderPath,
		Recursive: true,
		MaxKeys:   100000,
	})
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	base := strings.TrimPrefix(filepath.ToSlash(folderPath), "/")
	for _, obj := range objects {
		data, _, err := db.GetObject(obj.Path, user)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		objPath := filepath.ToSlash(obj.Path)
		name := strings.TrimPrefix(objPath, "/")
		if base != "" {
			name = strings.TrimPrefix(name, base)
			name = strings.TrimPrefix(name, "/")
		}
		if name == "" {
			name = filepath.Base(objPath)
		}
		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
