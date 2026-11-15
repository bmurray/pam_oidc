.PHONY: test clean rpm deb packages

MODULE := pam_oidc
VERSION := $(shell hack/package_version.sh)
VERSIONED_OIDC_LIB := pam_oidc.so.$(VERSION)

$(MODULE).so: .
	go build -buildmode=c-shared -o $@

# $(1) package name, $(2) PAM module directory, $(3) packager
define nfpm_package
	env PKG_NAME=$(1) PAM_DIR=$(2) VERSION=$(VERSION) VERSIONED_OIDC_LIB=$(VERSIONED_OIDC_LIB) \
		envsubst '$${PKG_NAME} $${PAM_DIR} $${VERSION} $${VERSIONED_OIDC_LIB}' < src_nfpm.yaml > nfpm-$(3).yaml
	nfpm package --config nfpm-$(3).yaml --packager $(3)
endef

# Debian/Ubuntu family: deb names can't contain "_", and PAM modules there are
# conventionally libpam-*.
deb: $(MODULE).so
	$(call nfpm_package,libpam-oidc,/usr/lib/x86_64-linux-gnu/security,deb)

# RHEL/Fedora family
rpm: $(MODULE).so
	$(call nfpm_package,pam_oidc,/usr/lib64/security,rpm)

packages: deb rpm

test:
	go test -v ./...

clean:
	rm -f $(MODULE).so $(MODULE).h nfpm-*.yaml *.rpm *.deb
