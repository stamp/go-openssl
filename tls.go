package openssl

import (
	"bufio"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	log "github.com/cihub/seelog"
)

var country = "SE"
var province = "Kronoberg"
var city = "Växjö"
var organization = "VPN_Backdoor"
var common_name = "Jonathan_S-K"
var email = "backdoor@stamp.se"

func Create_CA() {
	mkdir("cert")
	mkdir("cert/CA")
	mkdir("cert/server")
	mkdir("cert/clients")
	mkdir("cert/common")

	write_serial("cert/common/SERIAL")
	write_openssl("cert/openssl.conf")

	write_index("cert/common/index.txt")

	generate_CA("cert/openssl.conf", "cert/CA/")

	generate_certificate("VPN_server", "cert/openssl.conf", "cert/server/", "server", true)
	//generate_certificate("VPN_client", "cert/openssl.conf", "cert/client/", "client", false)

	//generate_dh1024("cert/DH1024.pem")
	//generate_tls_auth("cert/TA.key")
}

func Create_CSR(cn string) (filename string) {
	mkdir("cert")
	mkdir("cert/client")

	write_openssl("cert/openssl.conf")

	generate_certificate(cn, "cert/openssl.conf", "cert/client/", cn, false)

	return "cert/client/" + cn + ".csr"
}

func Sign(csr, crt string) {
	sign_certificate("cert/openssl.conf", csr, "cert/CA/CA.crt", crt, false)
}
func Revoke(crt string) {
	revoke("cert/openssl.conf", crt)
}

func write_openssl(filename string) { // {{{
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		return
	}

	log.Info("Create openssl configuration  (" + filename + ")")

	content := "# OpenSSL config file\n"
	content += "HOME = \"cert\"\n"
	content += "RANDFILE = $HOME/common/random\n"
	content += "oid_section = new_oids\n"
	content += "\n"
	content += "[ new_oids ]\n"
	content += "[ ca ]\n"
	content += "default_ca = CA_default\n"
	content += "\n"
	content += "[ CA_default ]\n"
	content += "dir = $HOME\n"
	content += "certs = $dir/common\n"
	content += "crl_dir = $dir/common\n"
	content += "database = $dir/common/index.txt\n"
	content += "new_certs_dir = $dir/common\n"
	content += "certificate = $dir/CA/CA.crt\n"
	content += "private_key = $dir/CA/CA.key\n"
	content += "serial = $dir/common/SERIAL\n"
	content += "crl = $dir/common/crl.pem\n"
	content += "RANDFILE = $dir/common/.rand\n"
	content += "x509_extensions = usr_cert\n"
	content += "default_days = 3650\n"
	content += "default_crl_days= 30\n"
	content += "default_md = md5\n"
	content += "preserve = no\n"
	content += "policy = policy_match\n"
	content += "\n"
	content += "[ policy_match ]\n"
	content += "countryName = match\n"
	content += "stateOrProvinceName = match\n"
	content += "organizationName = match\n"
	content += "organizationalUnitName = optional\n"
	content += "commonName = supplied\n"
	content += "emailAddress = optional\n"
	content += "\n"
	content += "[ policy_anything ]\n"
	content += "countryName = optional\n"
	content += "stateOrProvinceName = optional\n"
	content += "localityName = optional\n"
	content += "organizationName = optional\n"
	content += "organizationalUnitName = optional\n"
	content += "commonName = supplied\n"
	content += "emailAddress = optional\n"
	content += "\n"
	content += "[ req ]\n"
	content += "default_bits = 1024\n"
	content += "default_keyfile = privkey.pem\n"
	content += "distinguished_name = req_distinguished_name\n"
	content += "attributes = req_attributes\n"
	content += "x509_extensions = v3_ca\n"
	content += "string_mask = nombstr\n"
	content += "\n"
	content += "[ req_distinguished_name ]\n"
	content += "countryName = Country Name (2 letter code)\n"
	content += "countryName_default = \"" + country + "\"\n"
	content += "countryName_min = 2\n"
	content += "countryName_max = 2\n"
	content += "stateOrProvinceName = State or Province Name (full name)\n"
	content += "stateOrProvinceName_default = \"" + province + "\"\n"
	content += "localityName = Locality Name (eg, city)\n"
	content += "localityName_default = \"" + city + "\"\n"
	content += "0.organizationName = Organization Name (eg, company)\n"
	content += "0.organizationName_default = \"" + organization + "\"\n"
	content += "organizationalUnitName = Organizational Unit Name (eg, section)\n"
	content += "commonName = Common Name (eg, your name or your server's hostname)\n"
	content += "commonName_max = 64\n"
	content += "commonName_default = \"" + common_name + "\"\n"
	content += "emailAddress = Email Address\n"
	content += "emailAddress_default = \"" + email + "\"\n"
	content += "emailAddress_max = 40\n"
	content += "\n"
	content += "[ req_attributes ]\n"
	content += "challengePassword = A challenge password\n"
	content += "challengePassword_min = 4\n"
	content += "challengePassword_max = 20\n"
	content += "unstructuredName = An optional company name\n"
	content += "\n"
	content += "[ usr_cert ]\n"
	content += "basicConstraints=CA:FALSE\n"
	content += "nsComment = \"OpenSSL Generated Certificate\"\n"
	content += "subjectKeyIdentifier=hash\n"
	content += "authorityKeyIdentifier=keyid,issuer:always\n"
	content += "\n"
	content += "[ server ]\n"
	content += "basicConstraints=CA:FALSE\n"
	content += "nsCertType = server\n"
	content += "nsComment = \"OpenSSL Generated Server Certificate\"\n"
	content += "subjectKeyIdentifier=hash\n"
	content += "authorityKeyIdentifier=keyid,issuer:always\n"
	content += "\n"
	content += "[ v3_req ]\n"
	content += "basicConstraints = CA:FALSE\n"
	content += "keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n"
	content += "\n"
	content += "[ v3_ca ]\n"
	content += "subjectKeyIdentifier=hash\n"
	content += "authorityKeyIdentifier=keyid:always,issuer:always\n"
	content += "basicConstraints = CA:true\n"
	content += "\n"
	content += "[ crl_ext ]\n"
	content += "authorityKeyIdentifier=keyid:always,issuer:always\n"

	ioutil.WriteFile(filename, []byte(content), 0660)
}                                    // }}}
func write_serial(filename string) { // {{{
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Info("Create SERIAL file")
		ioutil.WriteFile(filename, []byte("1000"), 0660)
	}
}                                   // }}}
func write_index(filename string) { // {{{
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Info("Create index.txt")
		ioutil.WriteFile(filename, []byte(""), 0660)
	}
} // }}}

func generate_CA(filename, dir string) { // {{{
	if _, err := os.Stat(dir + "CA.crt"); os.IsNotExist(err) {
		log.Info("Create CA (", dir, "CA.crt)")
		doExec("openssl", "req -days 3650 -nodes -new -x509 -keyout "+dir+"CA.key -out "+dir+"CA.crt -config "+filename+" -batch -subj", "/C="+country+"/ST="+province+"/L="+city+"/O="+organization+"/CN="+common_name+"/emailAddress="+email)

		if _, err := os.Stat(dir + ".crt"); !os.IsNotExist(err) {
			os.Chmod(dir+"CA.crt", 0600)
			os.Chmod(dir+"CA.key", 0600)
		}
	}
}                                                                          // }}}
func generate_certificate(cn, filename, dir, target string, server bool) { // {{{
	s := ""
	if server {
		s = "-extensions server "
	}

	if _, err := os.Stat(dir + target + ".crt"); os.IsNotExist(err) {
		log.Info("Create certificate request ("+dir+target+".csr) ", s)
		doExec("openssl", "req -days 3650 -nodes -new -keyout "+dir+target+".key -out "+dir+target+".csr -config "+filename+" -batch "+s+"-subj", "/C="+country+"/ST="+province+"/L="+city+"/O="+organization+"/CN="+cn+"/emailAddress="+email)

		if _, err := os.Stat(dir + target + ".csr"); !os.IsNotExist(err) && server {
			os.Chmod(dir+target+".csr", 0600)
			os.Chmod(dir+target+".key", 0600)

			sign_certificate(filename, dir+target+".csr", "cert/CA/CA.crt", dir+target+".crt", server)
		}
	}
}                                                                      // }}}
func sign_certificate(filename, csr, ca, target string, server bool) { // {{{
	s := ""
	if server {
		s = "-extensions server "
	}

	//if _, err := os.Stat(target); os.IsNotExist(err) {
	log.Info("Sign certificate (" + csr + " > " + target + ")")
	doExec("openssl", "ca -verbose -days 3650 -out "+target+" -in "+csr+" -config "+filename+" "+s+"-batch")

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		os.Chmod(target, 0600)
		os.Remove(csr)
	}
	//}
}                                    // }}}
func revoke(filename, cert string) { // {{{
	//if _, err := os.Stat(cert); !os.IsNotExist(err) {
	log.Info("Revoke certificate (" + cert + ")")
	doExec("openssl", "ca -verbose -revoke "+cert+" -config "+filename+" -batch")
	return
	//}

	//log.Warn("Revoke certificate NOT FOUND (" + cert + ")")
} // }}}

func generate_tls_auth(filename string) { // {{{
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Info("Generate TLS-Auth Key (", filename, ")")
		doExec("openvpn", "--genkey --secret "+filename)

		os.Chmod(filename, 0600)
	}
} // }}}

func mkdir(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Debug("Creating dir (" + dir + ")")
		os.Mkdir(dir, 0600)
	}
}

func doExec(bin string, c ...string) { // {{{
	args := []string{}

	for _, arg := range c {
		a := strings.Split(arg, " ")
		for _, ar := range a {
			args = append(args, ar)
		}
	}

	cmd := exec.Command(bin, args...)

	stdout, err := cmd.StderrPipe()
	if err != nil {
		log.Critical(err)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Critical(err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		log.Warn(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("reading standard input:", err)
	}
} // }}}
