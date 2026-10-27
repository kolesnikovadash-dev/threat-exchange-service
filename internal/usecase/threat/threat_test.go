package threat

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/apperrors"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/models"
)

type fakeRepository struct {
	input models.ThreatInput
	calls int
}

func (f *fakeRepository) GetByMD5(_ context.Context, md5 string) (models.Threat, error) {
	f.calls++
	return models.Threat{MD5: md5}, nil
}

func (f *fakeRepository) Create(_ context.Context, in models.ThreatInput) (models.Threat, error) {
	f.calls++
	f.input = in
	return models.Threat{MD5: in.MD5, Name: in.Name}, nil
}

func (f *fakeRepository) Update(_ context.Context, in models.ThreatInput) (models.Threat, error) {
	f.calls++
	f.input = in
	return models.Threat{MD5: in.MD5, Name: in.Name}, nil
}

func TestCreateNormalizesInput(t *testing.T) {
	cases := []struct {
		name                            string
		input                           models.ThreatInput
		wantMD5, wantName, wantSeverity string
	}{
		{"uppercase", models.ThreatInput{MD5: "D41D8CD98F00B204E9800998ECF8427E", Name: "  Trojan.Test  ", Severity: strPtr("HIGH")}, "d41d8cd98f00b204e9800998ecf8427e", "Trojan.Test", "high"},
		{"lowercase", models.ThreatInput{MD5: "d41d8cd98f00b204e9800998ecf8427e", Name: "Worm.Test", Severity: strPtr("low")}, "d41d8cd98f00b204e9800998ecf8427e", "Worm.Test", "low"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepository{}
			got, err := NewThreatUsecase(repo).Create(context.Background(), tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if got.MD5 != tc.wantMD5 || got.Name != tc.wantName {
				t.Fatalf("unexpected response: %+v", got)
			}
			if repo.calls != 1 || *repo.input.Severity != tc.wantSeverity {
				t.Fatalf("unexpected repository input: %+v", repo.input)
			}
		})
	}
}

func strPtr(s string) *string { return &s }

func TestRejectsInvalidInputBeforeWriting(t *testing.T) {
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	cases := []struct {
		name  string
		input models.ThreatInput
	}{
		{"bad md5", models.ThreatInput{MD5: "oops", Name: "Test"}},
		{"empty name", models.ThreatInput{MD5: md5, Name: "  "}},
		{"too long name", models.ThreatInput{MD5: md5, Name: strings.Repeat("я", 256)}},
		{"unknown severity", models.ThreatInput{MD5: md5, Name: "Test", Severity: strPtr("severe")}},
		{"unknown type", models.ThreatInput{MD5: md5, Name: "Test", ThreatType: strPtr("rootkit")}},
		{"long description", models.ThreatInput{MD5: md5, Name: "Test", Description: strPtr(strings.Repeat("x", 2049))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepository{}
			_, err := NewThreatUsecase(repo).Create(context.Background(), tc.input)
			if !errors.Is(err, apperrors.ErrInvalidInput) || repo.calls != 0 {
				t.Fatalf("err=%v calls=%d", err, repo.calls)
			}
		})
	}
}

func TestUpdateUsesMD5FromURL(t *testing.T) {
	cases := []struct{ name, urlMD5, bodyMD5, wantMD5 string }{
		{"uppercase url", "D41D8CD98F00B204E9800998ECF8427E", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "d41d8cd98f00b204e9800998ecf8427e"},
		{"lowercase url", "b41d8cd98f00b204e9800998ecf8427e", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "b41d8cd98f00b204e9800998ecf8427e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepository{}
			_, err := NewThreatUsecase(repo).Update(context.Background(), tc.urlMD5, models.ThreatInput{MD5: tc.bodyMD5, Name: "Test"})
			if err != nil {
				t.Fatal(err)
			}
			if repo.input.MD5 != tc.wantMD5 {
				t.Fatalf("md5=%q want=%q", repo.input.MD5, tc.wantMD5)
			}
		})
	}
}

func TestGetRejectsMalformedMD5(t *testing.T) {
	cases := []string{"invalid-md5", "", "d41d8cd98f00b204e9800998ecf8427z"}
	for _, md5 := range cases {
		t.Run(md5, func(t *testing.T) {
			repo := &fakeRepository{}
			_, err := NewThreatUsecase(repo).GetByMD5(context.Background(), md5)
			if !errors.Is(err, apperrors.ErrInvalidInput) || repo.calls != 0 {
				t.Fatalf("err=%v calls=%d", err, repo.calls)
			}
		})
	}
}
