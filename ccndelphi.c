/**
 * @file ccnput.c
 * Replies with junk to every interest it receives (just like an old-fashioned
 * Greek oracle).
 * Note that if the same interest gets expressed twice and the request arrives
 * a different reply will be generated. This violates the CCN protocol but
 * should not be a problem for the scenarios this tool is useful for (which
 * would be stress testing the CCN infrastructure).
 *
 * A CCNx command-line utility. Probably.
 *
 * Pierluigi Rolando
 * Copyright (C) 2010 Washington University in St. Louis.
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>
#include <unistd.h>

static char *d_buffer;

static void
usage(const char *progname)
{
    fprintf(stderr,
            "%s [-hv] [-x freshness_seconds] [-s reply_size_in_bytes] ccnx:/a/b\n"
            " Generates random data and sends it to the local ccnd"
            " in reply to every interest it receives."
            "\n"
            "  -h - print this message and exit"
            "\n"
            "  -v - verbose"
            "\n"
            "  -x seconds - set FreshnessSeconds"
            "\n"
            "  -s bytes - set size of replies (default 1024)"
            "\n", progname);
    exit(1);
}



enum ccn_upcall_res
incoming_interest(
    struct ccn_closure *selfp,
    enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info)
{
    int res;
    struct ccn *ccn = selfp->data;
    
    switch (kind) {
        case CCN_UPCALL_INTEREST: {
		    struct ccn_charbuf *packet = NULL;

			//fprintf(stderr, "got interest\n");

			packet = ccn_charbuf_create();

			/* Extract URI from interest */
			unsigned name_start = info->pi->offset[CCN_PI_B_Name];
			unsigned name_size = info->pi->offset[CCN_PI_E_Name] - name_start;

			struct ccn_charbuf *name = NULL;
			name = ccn_charbuf_create();
			ccn_charbuf_append(name, info->interest_ccnb + name_start,
				name_size);

			/* Generate random payload */
			unsigned int size = selfp->intdata;
			char *buffer = d_buffer;
    
		    /* Create the signed content object, ready to go */
		    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
        	/* sp.sp_flags |= CCN_SP_FINAL_BLOCK; */
		    sp.type = CCN_CONTENT_DATA;

		    packet->length = 0;
		    res = ccn_sign_content(ccn, packet, name, &sp, buffer, size);
		    if (res != 0) {
		        fprintf(stderr, "Failed to encode ContentObject (res == %d)\n", res);
		        break;
		    }

			/* Send the reply */
			res = ccn_put(info->h, packet->buf, packet->length); 
		
			/* Destroy everything that had to be allocated */
			ccn_charbuf_destroy(&name);
		    ccn_charbuf_destroy(&packet);

            if (res >= 0)
				return(CCN_UPCALL_RESULT_INTEREST_CONSUMED);

			break;
		}
		default:
			break;
	}
    return(CCN_UPCALL_RESULT_OK);
}

int
main(int argc, char **argv)
{
    const char *progname = argv[0];
    struct ccn *ccn = NULL;

 	unsigned size = 1024;
    int res;

    struct ccn_closure in_interest = {.p=&incoming_interest};
    
    while ((res = getopt(argc, argv, "hs:")) != -1) {
        switch (res) {
 			case 's':
				size = atol(optarg);
				break;
            default:
            case 'h':
                usage(progname);
                break;
        }
    }

    argc -= optind;
    argv += optind;

	/* Allocate the payload buffer */
	d_buffer = malloc(sizeof(*d_buffer)*size);

    /* Connect to ccnd */
    ccn = ccn_create();
    if (ccn_connect(ccn, NULL) == -1) {
        perror("Could not connect to ccnd");
        exit(1);
    }


	/* Create the name for the prefix we're interested in */
	struct ccn_charbuf *catch_all = NULL;

	catch_all = ccn_charbuf_create();	
    if (argv[0] == NULL)
        usage(progname);
    res = ccn_name_from_uri(catch_all, argv[0]);
    if (res < 0) {
        fprintf(stderr, "%s: bad ccn URI: %s\n", progname, argv[0]);
        exit(1);
    }
    
	/* Allocate some working space for storing content */
	in_interest.intdata = size;
	in_interest.data = ccn;

	/* Set up a handler for interests */
	res = ccn_set_interest_filter(ccn, catch_all, &in_interest);
	if (res < 0) {
		fprintf(stderr, "Failed to register interest (res == %d)\n", res);
		exit(1);
	}

	/* Send a ping to tell CCNd we speak CCN */
	{
	    struct ccn_charbuf *name = NULL;
		struct ccn_charbuf *resultbuf = NULL;
		struct ccn_parsed_ContentObject pcobuf = { 0 };

	    name = ccn_charbuf_create();
		resultbuf = ccn_charbuf_create();

    	ccn_name_from_uri(name, "ccnx:/ccnx/ping");

		res = ccn_get(ccn, name, NULL, 50, resultbuf, &pcobuf, NULL, 0);

		ccn_charbuf_destroy(&name);
		ccn_charbuf_destroy(&resultbuf);
	}
    
	while((res = ccn_run(ccn, 10000)) >= 0)
		;

    ccn_destroy(&ccn);
    ccn_charbuf_destroy(&catch_all);
	free(d_buffer);
	d_buffer = NULL;

	return EXIT_SUCCESS;
}

