/* -*- c-file-style: "linux" -*-
   
   Copyright (C) 1996-2001 by Andrew Tridgell <tridge@samba.org>
   Copyright (C) Paul Mackerras 1996
   Copyright (C) 2001, 2002 by Martin Pool <mbp@samba.org>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "rsync.h"

time_t starttime = 0;

struct stats stats;

extern int verbose;

char init_dir[MAXPATHLEN];

// FIXME: cmsj: There used to be a wait_process() function here. We don't use it, but maybe it can come back to reduce the patch size?
static void report(int f)
{
	time_t t = time(NULL);
	extern int am_server;
	extern int am_sender;
	extern int am_daemon;
	extern int do_stats;
	extern int remote_version;
	int send_stats;

	if (do_stats) {
		/* These come out from every process */
		show_flist_stats();
	}

	if (am_daemon) {
		log_exit(0, __FILE__, __LINE__);
		if (f == -1 || !am_sender) return;
	}

	send_stats = verbose || (remote_version >= 20);
	if (am_server) {
		if (am_sender && send_stats) {
			int64 w;
			/* store total_written in a temporary
			    because write_longint changes it */
			w = stats.total_written;
			write_longint(f,stats.total_read);
			write_longint(f,w);
			write_longint(f,stats.total_size);
		}
		return;
	}

	/* this is the client */
	    
	if (!am_sender && send_stats) {
		int64 r;
		stats.total_written = read_longint(f);
		/* store total_read in a temporary, read_longint changes it */
		r = read_longint(f);
		stats.total_size = read_longint(f);
		stats.total_read = r;
	}

	if (do_stats) {
		if (!am_sender && !send_stats) {
		    /* missing the bytes written by the generator */
		    rprintf(FINFO, "\nCannot show stats as receiver because remote protocol version is less than 20\n");
		    rprintf(FINFO, "Use --stats -v to show stats\n");
		    return;
		}
		rprintf(FINFO,"\nNumber of files: %d\n", stats.num_files);
		rprintf(FINFO,"Number of files transferred: %d\n", 
		       stats.num_transferred_files);
		rprintf(FINFO,"Total file size: %.0f bytes\n", 
		       (double)stats.total_size);
		rprintf(FINFO,"Total transferred file size: %.0f bytes\n", 
		       (double)stats.total_transferred_size);
		rprintf(FINFO,"Literal data: %.0f bytes\n", 
		       (double)stats.literal_data);
		rprintf(FINFO,"Matched data: %.0f bytes\n", 
		       (double)stats.matched_data);
		rprintf(FINFO,"File list size: %d\n", stats.flist_size);
		rprintf(FINFO,"Total bytes written: %.0f\n", 
		       (double)stats.total_written);
		rprintf(FINFO,"Total bytes read: %.0f\n\n", 
		       (double)stats.total_read);
	}
	
	if (verbose || do_stats) {
		rprintf(FINFO,"wrote %.0f bytes  read %.0f bytes  %.2f bytes/sec\n",
		       (double)stats.total_written,
		       (double)stats.total_read,
		       (stats.total_written+stats.total_read)/(0.5 + (t-starttime)));
		rprintf(FINFO,"total size is %.0f  speedup is %.2f\n",
		       (double)stats.total_size,
		       (1.0*stats.total_size)/(stats.total_written+stats.total_read));
	}

	fflush(stdout);
	fflush(stderr);
}

// FIXME: cmsj: There used to be a show_malloc_stats() here, with an #ifdef HAVE_MALLINFO. We don't have mallinfo() or use show_malloc_stats() so maybe the code can safely come back to reduce the patch size?
// FIXME: cmsj: Similarly do_cmd() which we now don't use. And do_server_sender()
static char *get_local_name(struct file_list *flist,char *name)
{
	STRUCT_STAT st;
	extern int orig_umask;

	if (verbose > 2)
		rprintf(FINFO,"get_local_name count=%d %s\n", 
			flist->count, NS(name));

	if (!name) 
		return NULL;

	if (do_stat(name,&st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			if (!push_dir(name, 0)) {
				rprintf(FERROR,"push_dir %s : %s (1)\n",
					name,strerror(errno));
				exit_cleanup(RERR_FILESELECT);
			}
			return NULL;
		}
		if (flist->count > 1) {
			rprintf(FERROR,"ERROR: destination must be a directory when copying more than 1 file\n");
			exit_cleanup(RERR_FILESELECT);
		}
		return name;
	}

	if (flist->count <= 1)
		return name;

	if (do_mkdir(name,0777 & ~orig_umask) != 0) {
		rprintf(FERROR, RSYNC_NAME ": mkdir %s: %s\n",
			name, strerror(errno));
		exit_cleanup(RERR_FILEIO);
	} else {
		if (verbose > 0)
			rprintf(FINFO,"created directory %s\n",name);
	}

	if (!push_dir(name, 0)) {
		rprintf(FERROR, RSYNC_NAME ": push_dir %s: %s\n",
			name, strerror(errno));
		exit_cleanup(RERR_FILESELECT);
	}

	return NULL;
}

static int do_recv(int f_in,int f_out,struct file_list *flist,char *local_name)
{
	int pid;
	int status=0;
	int recv_pipe[2];
	int error_pipe[2];
	extern int preserve_hard_links;
	extern int delete_after;
	extern int recurse;
	extern int delete_mode;
	extern int remote_version;

	if (preserve_hard_links)
		init_hard_links(flist);

	if (!delete_after) {
		/* I moved this here from recv_files() to prevent a race condition */
		if (recurse && delete_mode && !local_name && flist->count>0) {
			delete_files(flist);
		}
	}

	// send the checksums and ensure local permissions
	generate_files_phase1(f_out,flist,local_name);

	// get the data
	recv_gen_files(f_in,f_out,flist,local_name);
	io_flush();
	report(f_in);
	io_flush();

	io_start_buffering(f_out);

	if (remote_version >= 24) {
		/* send a final goodbye message */
		write_int(f_out, -1);
	}
	io_flush();

	return status;
}

// FIXME: cmsj: There used to be a do_server_recv() here, we don't use it, but maybe it can come back to reduce the patch size?
// FIXME: cmsj: Similarly start_server()
/*
 * This is called once the connection has been negotiated.  It is used
 * for rsyncd, remote-shell, and local connections.
 */
int client_run(int f_in, int f_out, pid_t pid, int argc, char *argv[])
{
	struct file_list *flist = NULL;
	int status = 0, status2 = 0;
	char *local_name = NULL;
	extern int am_sender;
	extern int remote_version;
	extern pid_t cleanup_child_pid;
	extern int write_batch;
	extern int read_batch;
	extern struct file_list *batch_flist;
	int n;
	char *p;

	cleanup_child_pid = pid;

	set_nonblocking(f_in);
	set_nonblocking(f_out);

	setup_protocol(f_out,f_in);

	if (remote_version >= 23)
		io_start_multiplex_in(f_in);
	
	if (am_sender) {
		if (!read_batch) /*  dw -- don't write to pipe */
		    flist = send_file_list(f_out,argc,argv);
		if (verbose > 3) 
			rprintf(FINFO,"file list sent\n");

		send_files(flist,f_out,f_in);
		if (remote_version >= 24) {
			/* final goodbye message */		
			read_int(f_in);
		}
		report(-1);
		exit_cleanup(status);
	}

	if (argc == 0) {
		extern int list_only;
		list_only = 1;
	}
	
	if (!write_batch)
	    send_exclude_list(f_out);
	
	flist = recv_file_list(f_in);
	if (!flist || flist->count == 0) {
		rprintf(FINFO, "client: nothing to do: "
                        "perhaps you need to specify some filenames or "
                        "the --recursive option?\n");
		exit_cleanup(0);
	}
	
	// trim off the trailing slash unless it is root
	p = argv[0];
	n = strlen(p);
	if ((n > 1) && (p[n-1] == '/'))
		p[n-1] = '\0';

	local_name = get_local_name(flist, argv[0]);
	
	status = do_recv(f_in,f_out,flist,local_name);
	
	return (status);
}

static char *find_colon(char *s)
{
	char *p, *p2;

	p = strchr(s,':');
	if (!p) return NULL;
	
	/* now check to see if there is a / in the string before the : - if there is then
	   discard the colon on the assumption that the : is part of a filename */
	p2 = strchr(s,'/');
	if (p2 && p2 < p) return NULL;

	return p;
}


#ifndef NOSHELLORSERVER
static int copy_argv (char *argv[])
{
	int i;

	for (i = 0; argv[i]; i++) {
		if (!(argv[i] = strdup(argv[i]))) {
			rprintf (FERROR, "out of memory at %s(%d)\n",
				 __FILE__, __LINE__);
			return RERR_MALLOC;
		}
	}

	return 0;
}


/**
 * Start a client for either type of remote connection.  Work out
 * whether the arguments request a remote shell or rsyncd connection,
 * and call the appropriate connection function, then run_client.
 *
 * Calls either start_socket_client (for sockets) or do_cmd and
 * client_run (for ssh).
 **/
static int start_client(int argc, char *argv[])
{
	char *p;
	char *shell_machine = NULL;
	char *shell_path = NULL;
	char *shell_user = NULL;
	int ret;
	pid_t pid;
	int f_in,f_out;
	extern int local_server;
	extern int am_sender;
	extern char *shell_cmd;
	extern int rsync_port;
	extern int whole_file;
	extern int write_batch;
	extern int read_batch;
	int rc;

	/* Don't clobber argv[] so that ps(1) can still show the right
           command line. */
	if ((rc = copy_argv (argv)))
		return rc;

	if (strncasecmp(URL_PREFIX, argv[0], strlen(URL_PREFIX)) == 0) {
		char *host, *path;

		host = argv[0] + strlen(URL_PREFIX);
		p = strchr(host,'/');
		if (p) {
			*p = 0;
			path = p+1;
		} else {
			path="";
		}
		p = strchr(host,':');
		if (p) {
			rsync_port = atoi(p+1);
			*p = 0;
		}
		return start_socket_client(host, path, argc-1, argv+1);
	}

	if (!read_batch) {
	    p = find_colon(argv[0]);

	if (p) {
		if (p[1] == ':') { /* double colon */
			*p = 0;
			return start_socket_client(argv[0], p+2, argc-1, argv+1);
		}

		if (argc < 1) {
			usage(FERROR);
			exit_cleanup(RERR_SYNTAX);
		}

		am_sender = 0;
		*p = 0;
		shell_machine = argv[0];
		shell_path = p+1;
		argc--;
		argv++;
	} else {
		am_sender = 1;

		p = find_colon(argv[argc-1]);
		if (!p) {
			local_server = 1;
		} else if (p[1] == ':') {
			*p = 0;
			return start_socket_client(argv[argc-1], p+2, argc-1, argv);
		}

		if (argc < 2) {
			usage(FERROR);
			exit_cleanup(RERR_SYNTAX);
		}
		
		if (local_server) {
			shell_machine = NULL;
			shell_path = argv[argc-1];
		} else {
			*p = 0;
			shell_machine = argv[argc-1];
			shell_path = p+1;
		}
		argc--;
	}
	} else {
	    am_sender = 1;
	    local_server = 1;
	    shell_path = argv[argc-1];
	}

	if (shell_machine) {
		p = strchr(shell_machine,'@');
		if (p) {
			*p = 0;
			shell_user = shell_machine;
			shell_machine = p+1;
		}
	}

	if (verbose > 3) {
		rprintf(FINFO,"cmd=%s machine=%s user=%s path=%s\n",
			shell_cmd?shell_cmd:"",
			shell_machine?shell_machine:"",
			shell_user?shell_user:"",
			shell_path?shell_path:"");
	}
	
	if (!am_sender && argc > 1) {
		usage(FERROR);
		exit_cleanup(RERR_SYNTAX);
	}

	if (argc == 0 && !am_sender) {
		extern int list_only;
		list_only = 1;
	}
	
	pid = do_cmd(shell_cmd,shell_machine,shell_user,shell_path,&f_in,&f_out);
	
	ret = client_run(f_in, f_out, pid, argc, argv);

	fflush(stdout);
	fflush(stderr);

	return ret;
}

#else

/**
 * Start a client for a rsyncd connection.
 * Calls start_socket_client for sockets.
 **/
static int start_client(int argc, char *argv[])
{
	char *p;
	extern int local_server;
	extern int am_sender;

	// try for src=host::path
	p = find_colon(argv[0]);

	if (p) {
		if (p[1] == ':') { /* double colon */
			*p = 0;
			return start_socket_client(argv[0], p+2, argc-1, argv+1);
		}

		if (argc < 1) {
			usage(FERROR);
			exit_cleanup(RERR_SYNTAX);
		}

		am_sender = 0;
	} else {
		am_sender = 1;

		// try for dst=host::path
		p = find_colon(argv[argc-1]);
		if (!p) {
			local_server = 1;
		} else if (p[1] == ':') {
			*p = 0;
			return start_socket_client(argv[argc-1], p+2, argc-1, argv);
		}
	}

	usage(FERROR);
	exit_cleanup(RERR_SYNTAX);
	return 0;
}
#endif

#ifndef NOSHELLORSERVER
static RETSIGTYPE sigusr1_handler(int UNUSED(val)) {
	exit_cleanup(RERR_SIGNAL);
}

static RETSIGTYPE sigusr2_handler(int UNUSED(val)) {
	extern int log_got_error;
	if (log_got_error) _exit(RERR_PARTIAL);
	_exit(0);
}

static RETSIGTYPE sigchld_handler(int UNUSED(val)) {
#ifdef WNOHANG
	while (waitpid(-1, NULL, WNOHANG) > 0) ;
#endif
}


/**
 * This routine catches signals and tries to send them to gdb.
 *
 * Because it's called from inside a signal handler it ought not to
 * use too many library routines.
 *
 * @todo Perhaps use "screen -X" instead/as well, to help people
 * debugging without easy access to X.  Perhaps use an environment
 * variable, or just call a script?
 *
 * @todo The /proc/ magic probably only works on Linux (and
 * Solaris?)  Can we be more portable?
 **/
#ifdef MAINTAINER_MODE
static RETSIGTYPE rsync_panic_handler(int UNUSED(whatsig))
{
	char cmd_buf[300];
	int ret;
	sprintf(cmd_buf, 
		"xterm -display :0 -T Panic -n Panic "
		"-e gdb /proc/%d/exe %d", 
		getpid(), getpid());

	/* Unless we failed to execute gdb, we allow the process to
	 * continue.  I'm not sure if that's right. */
	ret = system(cmd_buf);
	if (ret)
		_exit(ret);
}
#endif

#endif

int main(int argc,char *argv[])
{       
	extern int am_root;
	extern int orig_umask;
	extern int dry_run;
#ifndef NOSHELLORSERVER
	extern int am_daemon;
	extern int am_server;
	int ret;
	extern int write_batch;
	int orig_argc;
	char **orig_argv;
#else
    int ret;
#endif

#ifndef NOSHELLORSERVER
	orig_argc = argc;
	orig_argv = argv;

	signal(SIGUSR1, sigusr1_handler);
	signal(SIGUSR2, sigusr2_handler);
	signal(SIGCHLD, sigchld_handler);
#ifdef MAINTAINER_MODE
	signal(SIGSEGV, rsync_panic_handler);
	signal(SIGFPE, rsync_panic_handler);
	signal(SIGABRT, rsync_panic_handler);
	signal(SIGBUS, rsync_panic_handler);
#endif /* def MAINTAINER_MODE */
#endif

	starttime = time(NULL);
#ifdef NOSHELLORSERVER
	getcwd((char *)init_dir, MAXPATHLEN-1);
#endif
	am_root = (getuid() == 0);

	memset(&stats, 0, sizeof(stats));

	if (argc < 2) {
		usage(FERROR);
		exit_cleanup(RERR_SYNTAX);
	}

	/* we set a 0 umask so that correct file permissions can be
	   carried across */
	orig_umask = (int)umask(0);

	if (!parse_arguments(&argc, (const char ***) &argv, 1)) {
                /* FIXME: We ought to call the same error-handling
                 * code here, rather than relying on getopt. */
		option_error();
		exit_cleanup(RERR_SYNTAX);
	}

#ifndef NOSHELLORSERVER
	signal(SIGINT,SIGNAL_CAST sig_int);
	signal(SIGHUP,SIGNAL_CAST sig_int);
	signal(SIGTERM,SIGNAL_CAST sig_int);

	/* Ignore SIGPIPE; we consistently check error codes and will
	 * see the EPIPE. */
	signal(SIGPIPE, SIG_IGN);

	/* Initialize push_dir here because on some old systems getcwd
	   (implemented by forking "pwd" and reading its output) doesn't
	   work when there are other child processes.  Also, on all systems
	   that implement getcwd that way "pwd" can't be found after chroot. */
	push_dir(NULL,0);

	if (write_batch && !am_server) {
	    write_batch_argvs_file(orig_argc, orig_argv);
	}

	if (am_daemon) {
		return daemon_main();
	}

	if (argc < 1) {
		usage(FERROR);
		exit_cleanup(RERR_SYNTAX);
	}

	if (dry_run)
		verbose = MAX(verbose,1);

#ifndef SUPPORT_LINKS
	if (!am_server && preserve_links) {
		rprintf(FERROR,"ERROR: symbolic links not supported\n");
		exit_cleanup(RERR_UNSUPPORTED);
	}
#endif

	if (am_server) {
		set_nonblocking(STDIN_FILENO);
		set_nonblocking(STDOUT_FILENO);
		start_server(STDIN_FILENO, STDOUT_FILENO, argc, argv);
	}

#endif
	ret = start_client(argc, argv);
	if (ret == -1) 
		exit_cleanup(RERR_STARTCLIENT);
	else
		exit_cleanup(ret);

	exit(ret);
	/* NOTREACHED */
	return(0);
}
