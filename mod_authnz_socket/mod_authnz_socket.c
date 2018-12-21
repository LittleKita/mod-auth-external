/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */


/* Uncomment if you want to use a HARDCODE'd check (default off) */
/* #define _HARDCODE_ */

#ifdef _HARDCODE_
  /* Uncomment if you want to use your own Hardcode (default off) */
  /*             MUST HAVE _HARDCODE_ defined above!                */
  /* #include "your_function_here.c" */
#endif


#include "apr_lib.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"
#include "apr_signal.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_sha1.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#include <netdb.h>
#endif

#ifndef STANDARD20_MODULE_STUFF
#error This module requires Apache 2.2.0 or later.
#endif

/* Names of environment variables used to pass data to authenticator */
#define ENV_USER	"USER"
#define ENV_PASS	"PASS"
#define ENV_GROUP	"GROUP"
#define ENV_URI		"URI"
#define ENV_IP		"IP"
#define ENV_HOST	"HOST"		/* Remote Host */
#define ENV_HTTP_HOST	"HTTP_HOST"	/* Local Host */
#define ENV_CONTEXT	"CONTEXT"	/* Arbitrary Data from Config */
/* Undefine this if you do not want cookies passed to the script */
#define ENV_COOKIE	"COOKIE"

/*
 * Structure for the module itself.  The actual definition of this structure
 * is at the end of the file.
 */
module AP_MODULE_DECLARE_DATA authnz_socket_module;

/*
 *  Data types for per-directory and per-server configuration
 */

typedef struct
{
    apr_array_header_t *auth_name; /* Auth keyword for current dir */
    char *context;		 /* Context string from AuthsocketContext */
    int  providecache;		 /* Provide auth data to mod_authn_socache? */

} authnz_socket_dir_config_rec;


typedef struct
{
    apr_table_t *auth_host;	 /* Hash mapping auth keywords to paths */

    apr_table_t *auth_port;	 /* Hash mapping auth keywords to paths */

} authnz_socket_svr_config_rec;


/* mod_authn_socache's function for adding credentials to its cache */
static APR_OPTIONAL_FN_TYPE(ap_authn_cache_store) *authn_cache_store = NULL;


/* Creators for per-dir and server configurations.  These are called
 * via the hooks in the module declaration to allocate and initialize
 * the per-directory and per-server configuration data structures declared
 * above. */

static void *create_authnz_socket_dir_config(apr_pool_t *p, char *d)
{
    authnz_socket_dir_config_rec *dir= (authnz_socket_dir_config_rec *)
	apr_palloc(p, sizeof(authnz_socket_dir_config_rec));

    dir->auth_name= apr_array_make(p,2,sizeof(const char *)); /* no default */
    dir->context= NULL;		/* no default */
    dir->providecache= 0;	/* default to off */
    return dir;
}

static void *create_authnz_socket_svr_config( apr_pool_t *p, server_rec *s)
{
    authnz_socket_svr_config_rec *svr= (authnz_socket_svr_config_rec *)
	apr_palloc(p, sizeof(authnz_socket_svr_config_rec));

    svr->auth_host=    apr_table_make(p, 4);
    svr->auth_port=    apr_table_make(p, 4);
    /* Note: 4 is only initial hash size - they can grow bigger) */

    return (void *)svr;
}

/* Handler for a DefinesocketAuth server config line */
static const char *def_extauth(cmd_parms *cmd, void *dummy, const char *keyword,
				const char *host, const char *port)
{
    authnz_socket_svr_config_rec *svr= (authnz_socket_svr_config_rec *)
	ap_get_module_config( cmd->server->module_config,
	    &authnz_socket_module);

    apr_table_set( svr->auth_host,   keyword, host );
    apr_table_set( svr->auth_port,   keyword, port );

    return NULL;
}

/* Append an argument to an array defined by the offset */
static const char *append_array_slot(cmd_parms *cmd, void *struct_ptr,
				const char *arg)
{
    int offset = (int)(long)cmd->info;
    apr_array_header_t *array=
    	*(apr_array_header_t **)((char *)struct_ptr + offset);

    *(const char **)apr_array_push(array)= apr_pstrdup(array->pool, arg);

    return NULL;
}


/* Config file directives for this module */
static const command_rec authnz_socket_cmds[] =
{
    AP_INIT_ITERATE("AuthSocket",
	append_array_slot,
	(void *)APR_OFFSETOF(authnz_socket_dir_config_rec,auth_name),
	OR_AUTHCFG,
	"one (or more) keywords indicating which authenticators to use"),

    AP_INIT_TAKE3("DefineSocketAuth",
	def_extauth,
	NULL,
	RSRC_CONF,
	"a keyword followed by auth host and port to authentictor"),

    AP_INIT_TAKE1("AuthSocketContext",
	ap_set_string_slot,
	(void *)APR_OFFSETOF(authnz_socket_dir_config_rec, context),
	OR_AUTHCFG,
	"An arbitrary context string to pass to the authenticator in the "
	ENV_CONTEXT " environment variable"),

    AP_INIT_FLAG("AuthSocketProvideCache",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authnz_socket_dir_config_rec, providecache),
	OR_AUTHCFG,
	"Should we forge authentication credentials for mod_authn_socache?"),

    { NULL }
};

/* Run an socket authentication program using the given port for passing
 * in the data.  The login name is always passed in.   Dataname is "GROUP" or
 * "PASS" and data is the group list or password being checked.  To launch
 * a detached daemon, run this with extport=NULL.
 *
 * If the authenticator was run, we return the numeric code from the
 * authenticator, normally 0 if the login was valid, some small positive
 * number if not.  If we were not able to run the authenticator, we log
 * an error message and return a numeric error code:
 *
 *   -1   Could not execute authenticator, usually a path or permission problem
 *   -2   The socket authenticator crashed or was killed.
 *   -3   Could not create process attribute structure
 *   -4   apr_proc_wait() did not return a status code.  Should never happen.
 *   -5   apr_proc_wait() returned before child finished.  Should never happen.
 */
static int exec_socket(const char *chost, const char *cport, const request_rec *r, const char *dataname, const char *data)
{
    conn_rec *c= r->connection;

    /* Set various flags based on the execution port */

    /* Create the environment for the child.  Daemons don't get these, they
     * just inherit apache's environment variables.
     */

    struct hostent *he = gethostbyname(chost);
    if(he == NULL) {
        herror("gethostbyname");
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
	    "could not resolve hostname: %s", chost);
	    return -1;
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) {
        perror("socket");
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
	    "could not create socket");
	    return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(cport));
    memcpy(&addr.sin_addr, he->h_addr, sizeof(addr.sin_addr));

//    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, "connect to %d.%d.%d.%d:%d", he->h_addr[0], he->h_addr[1], he->h_addr[2], he->h_addr[3], atoi(cport));

    if(connect(s, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) < 0) {
        perror("socket");
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
	    "could connect socket %s:%d", chost, atoi(cport));
	    close(s);
	    return -1;
    }

    FILE *sock = fdopen(s, "r+");
    // Disable buffer:
    setvbuf(sock, NULL, _IONBF, 0);

	const char *cookie, *host, *remote_host;
	authnz_socket_dir_config_rec *dir= (authnz_socket_dir_config_rec *)
	    ap_get_module_config(r->per_dir_config, &authnz_socket_module);

    fprintf(sock, "%s=%s\r\n", ENV_USER, r->user);
    fprintf(sock, "%s=%s\r\n", dataname, data);

	remote_host= ap_get_remote_host(c, r->per_dir_config, REMOTE_HOST,NULL);
	if (remote_host != NULL)
        fprintf(sock, "%s=%s\r\n", ENV_HOST, remote_host);

	if (r->useragent_ip)
        fprintf(sock, "%s=%s\r\n", ENV_IP, r->useragent_ip);

	if (r->uri)
        fprintf(sock, "%s=%s\r\n", ENV_URI, r->uri);

	if ((host= apr_table_get(r->headers_in, "Host")) != NULL)
        fprintf(sock, "%s=%s\r\n", ENV_HTTP_HOST, host);

	if (dir->context)
        fprintf(sock, "%s=%s\r\n", ENV_CONTEXT, dir->context);

	if ((cookie= apr_table_get(r->headers_in, "Cookie")) != NULL)
        fprintf(sock, "%s=%s\r\n", ENV_COOKIE, cookie);

    fprintf(sock, "\r\n");

    char buf[3];
    memset(buf, 0, sizeof(buf));
    int len = read(s, buf, 2);
    fclose(sock);
    close(s);

    if(len == 2 && buf[0] == 'O' && buf[1] == 'K') {
        return 0;
    }

    return -1;
}

/* Mod_authn_socache wants us to pass it the username and the encrypted
 * password from the user database to cache. But we have no access to the
 * actual user database - only the socket authenticator can see that -
 * and chances are, the passwords there aren't encrypted in any way that
 * mod_authn_socache would understand anyway. So instead, after successful
 * authentications only, we take the user's plain text password, encrypt
 * that using an algorithm mod_authn_socache will understand, and cache that
 * as if we'd actually gotten it from a password database.
 */
void mock_turtle_cache(request_rec *r, const char *plainpw)
{
    char cryptpw[120];

    /* Authn_cache_store will be null if mod_authn_socache does not exist.
     * If it does exist, but is not set up to cache us, then
     * authn_cache_store() will do nothing, which is why we turn this off
     * with "AuthsocketProvideCache Off" to avoid doing the encryption
     * for no reason. */
    if (authn_cache_store != NULL)
    {
	apr_sha1_base64(plainpw,strlen(plainpw),cryptpw);
        authn_cache_store(r, "socket", r->user, NULL, cryptpw);
    }
}


/* Password checker for basic authentication - given a login/password,
 * check if it is valid.  Returns one of AUTH_DENIED, AUTH_GRANTED,
 * or AUTH_GENERAL_ERROR. */

static authn_status authn_socket_check_password(request_rec *r,
	const char *user, const char *password)
{
    const char *extname, *exthost, *extport;
    int i;
    authnz_socket_dir_config_rec *dir= (authnz_socket_dir_config_rec *)
	    ap_get_module_config(r->per_dir_config, &authnz_socket_module);

    authnz_socket_svr_config_rec *svr= (authnz_socket_svr_config_rec *)
	    ap_get_module_config(r->server->module_config,
		&authnz_socket_module);
    int code= 1;

    /* Check if we are supposed to handle this authentication */
    if (dir->auth_name->nelts == 0)
    {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	    "No AuthSocket name has been set");
	return AUTH_GENERAL_ERROR;
    }

    for (i= 0; i < dir->auth_name->nelts; i++)
    {
	extname= ((const char **)dir->auth_name->elts)[i];

	/* Get the host associated with that socket */
	if (!(exthost= apr_table_get(svr->auth_host, extname)))
	{
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		"Invalid AuthSocket keyword (%s)", extname);
	    return AUTH_GENERAL_ERROR;
	}

	/* Get the port associated with that socket */
	if (!(extport= apr_table_get(svr->auth_port, extname)))
	{
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		"Invalid AuthSocket keyword (%s)", extname);
	    return AUTH_GENERAL_ERROR;
	}

	/* Do the authentication, by the requested port */
    code= exec_socket(exthost, extport, r, ENV_PASS, password);

	/* If return code was zero, authentication succeeded */
	if (code == 0)
	{
	    if (dir->providecache) mock_turtle_cache(r, password);
	    return AUTH_GRANTED;
	}

	/* Log a failed authentication */
	errno= 0;
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	    "AuthSocket %s [%s]: Failed (%d) for user %s",
	    extname, exthost, code, r->user);
    }
    /* If no authenticators succeed, refuse authentication */
    return AUTH_DENIED;
}

/* This is called after all modules have been initialized to acquire pointers
 * to some functions from other modules that we would like to use if they are
 * available. */
static void opt_retr(void)
{
    /* Get authn_cache_store from mod_authn_socache */
    authn_cache_store=
	APR_RETRIEVE_OPTIONAL_FN(ap_authn_cache_store);
}

/* This tells mod_auth_basic and mod_auth_digest what to call for
 * authentication. */
static const authn_provider authn_socket_provider =
{
    &authn_socket_check_password,
    NULL	/* No support for digest authentication */
};

/* Register this module with Apache */
static void register_hooks(apr_pool_t *p)
{
    /* Register authn provider */
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "socket",
	    AUTHN_PROVIDER_VERSION,
	    &authn_socket_provider, AP_AUTH_INTERNAL_PER_CONF);

    /* Ask for opt_retr() to be called after all modules have registered */
    ap_hook_optional_fn_retrieve(opt_retr, NULL, NULL, APR_HOOK_MIDDLE);
}


AP_DECLARE_MODULE(authnz_socket) = {
    STANDARD20_MODULE_STUFF,
    create_authnz_socket_dir_config,	  /* create per-dir config */
    NULL,			  /* merge per-dir config - dflt is override */
    create_authnz_socket_svr_config, /* create per-server config */
    NULL,			  /* merge per-server config */
    authnz_socket_cmds,	  /* command apr_table_t */
    register_hooks		  /* register hooks */
};
