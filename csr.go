package openssl

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"regexp"

	log "github.com/cihub/seelog"
)

type CSR struct {
	//path string
	//key  string

	content    []byte
	contentKey []byte
}

func (o *Openssl) LoadCSR(filename, keyfile string) (*CSR, error) {
	var err error
	o.Init()

	c := &CSR{}
	//c.path = filename
	//c.key = keyfile

	c.content, err = ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	c.contentKey, err = ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (o *Openssl) CreateCSR(cn string) (*CSR, error) {
	var err error
	o.Init()

	c := &CSR{}
	//c.path = filename
	//c.key = keyfile

	content, err := exec.Command(
		"openssl", "req",
		"-days", "3650",
		"-nodes",
		"-new",
		"-keyout", "/dev/stdout",
		"-out", "/dev/stdout",
		"-config", o.GetConfigFile(),
		"-batch",
		"-extensions", "server",
		"-utf8",
		"-subj", "/C="+o.Country+"/ST="+o.Province+"/L="+o.City+"/O="+o.Organization+"/CN="+cn+"/emailAddress="+o.Email,
	).Output()
	if err != nil {
		log.Error(err)
		return nil, err
	}

	reCert := regexp.MustCompile("(?ms)-----BEGIN CERTIFICATE REQUEST-----(.+)-----END CERTIFICATE REQUEST-----")
	reKey := regexp.MustCompile("(?ms)-----BEGIN PRIVATE KEY-----(.+)-----END PRIVATE KEY-----")

	c.content = reCert.Find(content)
	c.contentKey = reKey.Find(content)

	if len(c.content) == 0 {
		err = fmt.Errorf("Generated csr is 0 long")
		return nil, err
	}

	if len(c.contentKey) == 0 {
		err = fmt.Errorf("Generated csr key is 0 long")
		return nil, err
	}

	//if err = ioutil.WriteFile(c.path, c.content, 0600); err != nil {
	//return nil, err
	//}
	//if err = ioutil.WriteFile(c.key, c.contentKey, 0600); err != nil {
	//return nil, err
	//}

	return c, nil
}
