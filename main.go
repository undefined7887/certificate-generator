package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/elastic/go-sysinfo"
)

func main() {
	if err := os.MkdirAll("out", 0o700); err != nil {
		fatal("failed to create out directory", err)
	}

	domain := getDomain()
	expires := getExpires()
	wildcard := getWildcard()

	regenerate := true
	install := false

	if _, err := os.Stat("out/root.key"); err == nil {
		regenerate = getRegenerate()
	} else {
		if !os.IsNotExist(err) {
			fatal("failed file stat", err)
		}
	}

	if regenerate {
		install = getInstall()

		generateRootPrivate()
		generateRootCertificate(expires)

		if install {
			install = installRoot()
		}

	}

	generateClientPrivate(domain)
	generateClientRequest(domain, wildcard)
	generateClientCertificate(domain, expires, wildcard)

	result(domain, regenerate, install)
}

func getDomain() string {
	return inputNonEmpty("Domain []")
}

func getExpires() string {
	return input("Lifetime (days) [1024]", "1024")
}

func getWildcard() bool {
	return inputBool("Wildcard [true]", true)
}

func getRegenerate() bool {
	return inputBool("Root certificate detected, regenerate? [false]", false)
}

func getInstall() bool {
	return inputBool("Try to install automatically? [true]", true)
}

func generateRootPrivate() {
	command(
		"Generating root private key",
		"openssl", "ecparam", "-name", "prime256v1", "-genkey", "-out", "out/root.key",
	)
}

func generateRootCertificate(expire string) {
	command(
		"Generating root certificate",
		"openssl", "req", "-x509", "-new", "-nodes", "-key", "out/root.key", "-sha256", "-days", expire, "-subj", "/CN=local", "-out", "out/root.crt",
	)
}

func generateClientPrivate(domain string) {
	command(
		"Generating client private key",
		"openssl", "ecparam", "-name", "prime256v1", "-genkey", "-out", "out/"+domain+".key",
	)
}

func generateClientRequest(domain string, wildcard bool) {
	resultDomain := domain

	if wildcard {
		resultDomain = "*." + domain
	}

	command(
		"Generating client certificate request",
		"openssl", "req", "-new", "-sha256", "-nodes", "-key", "out/"+domain+".key", "-subj", "/CN="+resultDomain, "-out", "out/"+domain+".csr",
	)
}

func generateClientCertificate(domain, expire string, wildcard bool) {
	resultDomain := domain

	if wildcard {
		resultDomain = "*." + domain
	}

	v3 := fmt.Sprintf(v3Format, resultDomain)
	if err := os.WriteFile("out/v3.ext", []byte(v3), 0o600); err != nil {
		fatal("failed to create v3.ext file", err)
	}

	command(
		"Generating client certificate",
		"openssl", "x509", "-req", "-in", "out/"+domain+".csr", "-CA", "out/root.crt", "-CAkey", "out/root.key", "-CAcreateserial", "-out", "out/"+domain+".crt", "-days", expire, "-sha256", "-extfile", "out/v3.ext",
	)

	os.Remove("out/v3.ext")
	os.Remove("out/" + domain + ".csr")
}

func installRoot() bool {
	host, err := sysinfo.Host()
	if err != nil {
		fmt.Println("\nFailed to get host info")
		return false
	}

	info := host.Info()

	switch info.OS.Family {
	case "redhat":
		command(
			"Copying root certificate",
			"sudo", "cp", "out/root.crt", "/etc/pki/ca-trust/source/anchors/certificate-generator-root.crt",
		)

		command(
			"Installing root certificate",
			"sudo", "update-ca-trust",
		)
		return true

	default:
		fmt.Println("\nAutomatic install not supported on", info.OS.Family)
		input("Press enter to continue...", "")

		return false
	}
}

func result(domain string, regenerated, installed bool) {
	installReminder := "\nAdd out/root.crt to your system trust centre"
	if !regenerated || regenerated && installed {
		installReminder = ""
	}

	fmt.Printf(`
======================================

Certificates generated!%s

Key:	out/%s.key 
Cert:	out/%s.crt

======================================`, installReminder, domain, domain)
}

func input(hint, defaultResult string) string {
	fmt.Printf("%s: ", hint)

	res, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fatal("failed to read string from stdin", err)
	}

	// Removing \n
	res = res[:len(res)-1]

	if res == "" {
		res = defaultResult
	}

	return res
}

func inputBool(hint string, defaultResult bool) bool {
	for {
		str := input(hint, strconv.FormatBool(defaultResult))

		result, err := strconv.ParseBool(str)
		if err != nil {
			fmt.Println("expected true or false")
			continue
		}

		return result
	}
}

func inputNonEmpty(hint string) string {
	for {
		result := input(hint, "")

		if result == "" {
			fmt.Println("expected string")
			continue
		}

		return result
	}
}

func command(hint, name string, args ...string) {
	fmt.Println()
	fmt.Printf("# %s\n", hint)

	cmd := exec.Command(name, args...)
	fmt.Printf("-> %s\n", cmd.String())

	if out, err := cmd.CombinedOutput(); err != nil {
		fatal("command failed", errors.New(string(out)))
	}
}

func fatal(reason string, err error) {
	fmt.Printf("%s: %v\n", reason, err)
	os.Exit(1)
}
