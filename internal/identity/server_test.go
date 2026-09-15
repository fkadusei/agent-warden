package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServerCertificateOverMutualTLS(t *testing.T) {
	// A real TLS handshake checks the real clock, so this CA cannot use the fixed
	// test time the other identity tests use.
	start := time.Now()
	ca, err := NewCA("Warden Test Root", mlkey(t), start.Add(-time.Hour), start.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	serverKey, agentKey := mlkey(t), mlkey(t)
	serverDER, err := ca.IssueServer([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, serverKey.PublicKey(), start.Add(-time.Minute), start.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	taskDER, err := ca.IssueTask(claims, agentKey.PublicKey(), start.Add(-time.Minute), start.Add(MaxTaskLifetime))
	if err != nil {
		t.Fatal(err)
	}

	var seen *Task
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		task, err := VerifyTask(r.TLS.PeerCertificates[0].Raw, ca.Pool(), time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		seen = task
		io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool(),
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	defer srv.Close()

	client := func(certs []tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: ca.Pool(), Certificates: certs, MinVersion: tls.VersionTLS13, VerifyConnection: CheckServer,
		}}}
	}

	resp, err := client([]tls.Certificate{{Certificate: [][]byte{taskDER}, PrivateKey: agentKey}}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || seen == nil || seen.TaskClaims != claims {
		t.Fatalf("status %d, task %+v", resp.StatusCode, seen)
	}

	if _, err := client(nil).Get(srv.URL); err == nil {
		t.Fatal("a client without a task credential was accepted")
	}

	// The server certificate is not a task credential, and a task credential is not
	// a server certificate.
	if _, err := VerifyTask(serverDER, ca.Pool(), time.Now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("server certificate as task credential: got %v", err)
	}
	cert, _ := x509.ParseCertificate(taskDER)
	if err := CheckServer(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("task credential as server certificate: got %v", err)
	}
}

// A certificate from the same root that is not a Warden server certificate must not
// pass as the gateway, even though Go's chain and host-name checks accept it.
func TestCheckServerRejectsOtherCertificatesFromTheRoot(t *testing.T) {
	ca := newCA(t)
	impostorKey := mlkey(t)
	der := raw(t, ca, &x509.Certificate{
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"},
	}, impostorKey.PublicKey())
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckServer(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
	if err := CheckServer(tls.ConnectionState{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no certificate: got %v, want ErrInvalid", err)
	}
}

func TestIssueServerRefuses(t *testing.T) {
	ca := newCA(t)
	pub := mlkey(t).PublicKey()
	cases := map[string]func() error{
		"no names": func() error {
			_, err := ca.IssueServer(nil, nil, pub, now, now.Add(time.Hour))
			return err
		},
		"wildcard": func() error {
			_, err := ca.IssueServer([]string{"*.example.com"}, nil, pub, now, now.Add(time.Hour))
			return err
		},
		"too long": func() error {
			_, err := ca.IssueServer([]string{"warden.example"}, nil, pub, now, now.Add(MaxServerLifetime+time.Hour))
			return err
		},
		"underscore in name": func() error {
			_, err := ca.IssueServer([]string{"bad_name.example"}, nil, pub, now, now.Add(time.Hour))
			return err
		},
	}
	for name, issue := range cases {
		t.Run(name, func(t *testing.T) {
			if issue() == nil {
				t.Fatal("issued")
			}
		})
	}
}
