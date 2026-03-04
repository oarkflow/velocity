package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
)

type PKCS11SecretSealer struct {
	cfg     PKCS11SecretConfig
	module  *pkcs11.Ctx
	session pkcs11.SessionHandle
	key     pkcs11.ObjectHandle
	slot    uint
	mu      sync.Mutex
	closed  bool
}

func NewPKCS11SecretSealer(cfg PKCS11SecretConfig) (*PKCS11SecretSealer, error) {
	module := pkcs11.New(cfg.ModulePath)
	if module == nil {
		return nil, fmt.Errorf("pkcs11: unable to load module %s", cfg.ModulePath)
	}
	if err := module.Initialize(); err != nil && err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return nil, fmt.Errorf("pkcs11 initialize: %w", err)
	}
	slot, err := selectPKCS11Slot(module, cfg)
	if err != nil {
		module.Finalize()
		return nil, err
	}
	session, err := module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		module.Finalize()
		return nil, fmt.Errorf("pkcs11 open session: %w", err)
	}
	if err := module.Login(session, pkcs11.CKU_USER, cfg.PIN); err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		module.CloseSession(session)
		module.Finalize()
		return nil, fmt.Errorf("pkcs11 login: %w", err)
	}
	handle, err := ensurePKCS11WrappingKey(module, session, cfg)
	if err != nil {
		module.Logout(session)
		module.CloseSession(session)
		module.Finalize()
		return nil, err
	}
	return &PKCS11SecretSealer{
		cfg:     cfg,
		module:  module,
		session: session,
		key:     handle,
		slot:    slot,
	}, nil
}

func (p *PKCS11SecretSealer) Provider() string {
	return "pkcs11"
}

func (p *PKCS11SecretSealer) EncryptSecret(secret []byte) (*SealedHardwareSecret, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("pkcs11 provider closed")
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	params := pkcs11.NewGCMParams(nonce, nil, 128)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	if err := p.module.EncryptInit(p.session, mech, p.key); err != nil {
		return nil, fmt.Errorf("pkcs11 encrypt init: %w", err)
	}
	ciphertext, err := p.module.Encrypt(p.session, secret)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 encrypt: %w", err)
	}
	return &SealedHardwareSecret{
		Version:    1,
		Provider:   p.Provider(),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		KeyLabel:   p.cfg.KeyLabel,
		CreatedAt:  time.Now().UTC(),
		Metadata: map[string]string{
			"module":      p.cfg.ModulePath,
			"tokenLabel":  p.cfg.TokenLabel,
			"tokenSerial": p.cfg.TokenSerial,
			"slot":        fmt.Sprintf("%d", p.slot),
		},
	}, nil
}

func (p *PKCS11SecretSealer) DecryptSecret(seal *SealedHardwareSecret) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("pkcs11 provider closed")
	}
	nonce, err := base64.StdEncoding.DecodeString(seal.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(seal.Ciphertext)
	if err != nil {
		return nil, err
	}
	params := pkcs11.NewGCMParams(nonce, nil, 128)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	if err := p.module.DecryptInit(p.session, mech, p.key); err != nil {
		return nil, fmt.Errorf("pkcs11 decrypt init: %w", err)
	}
	plaintext, err := p.module.Decrypt(p.session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 decrypt: %w", err)
	}
	return plaintext, nil
}

func (p *PKCS11SecretSealer) Describe() map[string]string {
	return map[string]string{
		"provider":   p.Provider(),
		"module":     p.cfg.ModulePath,
		"keyLabel":   p.cfg.KeyLabel,
		"tokenLabel": p.cfg.TokenLabel,
		"slot":       fmt.Sprintf("%d", p.slot),
	}
}

func (p *PKCS11SecretSealer) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.module != nil {
		_ = p.module.Logout(p.session)
		_ = p.module.CloseSession(p.session)
		_ = p.module.Finalize()
	}
}

func selectPKCS11Slot(module *pkcs11.Ctx, cfg PKCS11SecretConfig) (uint, error) {
	slots, err := module.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 slot list: %w", err)
	}
	if len(slots) == 0 {
		return 0, errors.New("pkcs11: no slots available")
	}
	if cfg.SlotID != nil {
		return *cfg.SlotID, nil
	}
	if cfg.TokenLabel == "" && cfg.TokenSerial == "" {
		return slots[0], nil
	}
	for _, slot := range slots {
		info, err := module.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		label := strings.TrimSpace(info.Label)
		serial := strings.TrimSpace(info.SerialNumber)
		if cfg.TokenLabel != "" && label == cfg.TokenLabel {
			return slot, nil
		}
		if cfg.TokenSerial != "" && serial == cfg.TokenSerial {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("pkcs11: no slot matched label %q or serial %q", cfg.TokenLabel, cfg.TokenSerial)
}

func ensurePKCS11WrappingKey(module *pkcs11.Ctx, session pkcs11.SessionHandle, cfg PKCS11SecretConfig) (pkcs11.ObjectHandle, error) {
	key, err := findPKCS11Key(module, session, cfg.KeyLabel)
	if err != nil {
		return 0, err
	}
	if key != 0 {
		return key, nil
	}
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, cfg.KeyLabel),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	handle, err := module.GenerateKey(session, mech, tmpl)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 generate key: %w", err)
	}
	return handle, nil
}

func findPKCS11Key(module *pkcs11.Ctx, session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	if strings.TrimSpace(label) == "" {
		return 0, nil
	}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := module.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("pkcs11 find objects init: %w", err)
	}
	handles, _, err := module.FindObjects(session, 1)
	module.FindObjectsFinal(session)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 find objects: %w", err)
	}
	if len(handles) == 0 {
		return 0, nil
	}
	return handles[0], nil
}
