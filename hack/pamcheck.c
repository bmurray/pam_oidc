// pamcheck: authenticate through a PAM service non-interactively, answering
// every prompt with the given password. A minimal pamtester replacement that
// builds the same on glibc and musl, used by hack/smoke-test.sh.
//
//   pamcheck <service> <user> <password>   (exit 0 on PAM_SUCCESS)

#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *pw)
{
	struct pam_response *r = calloc(n, sizeof(*r));
	if (!r)
		return PAM_BUF_ERR;
	for (int i = 0; i < n; i++) {
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
			r[i].resp = strdup(pw);
	}
	*resp = r;
	return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "usage: %s <service> <user> <password>\n", argv[0]);
		return 2;
	}
	struct pam_conv c = { conv, argv[3] };
	pam_handle_t *h = NULL;
	int rc = pam_start(argv[1], argv[2], &c, &h);
	if (rc == PAM_SUCCESS)
		rc = pam_authenticate(h, 0);
	fprintf(stderr, "pamcheck: %s\n", pam_strerror(h, rc));
	pam_end(h, rc);
	return rc == PAM_SUCCESS ? 0 : 1;
}
