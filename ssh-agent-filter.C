/*
 * ssh-agent-filter.C -- filtering proxy for ssh-agent meant to be forwarded to untrusted servers
 *
 * Copyright (C) 2013 Timo Weingärtner <timo@tiwe.de>
 *
 * This file is part of ssh-agent-filter.
 *
 * ssh-agent-filter is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ssh-agent-filter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ssh-agent-filter.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include <boost/iostreams/stream_buffer.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
namespace io = boost::iostreams;

#include <string>
#include <vector>
#include <set>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <nettle/md5.h>
#include <nettle/base64.h>
#include <nettle/base16.h>

#include "rfc4251.h"
#include "ssh-agent.h"
#include "version.h"

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

std::vector<std::string> allowed_b64;
std::vector<std::string> allowed_md5;
std::vector<std::string> allowed_comment;
std::vector<std::string> confirmed_b64;
std::vector<std::string> confirmed_md5;
std::vector<std::string> confirmed_comment;
std::set<rfc4251string> allowed_pubkeys;
std::map<rfc4251string, std::string> confirmed_pubkeys;
bool debug{false};
bool all_confirmed{false};
std::string saf_name;
fs::path path;


std::string md5_hex (std::string const & s) {
	struct md5_ctx ctx;
	md5_init(&ctx);
	md5_update(&ctx, s.size(), reinterpret_cast<uint8_t const *>(s.data()));
	uint8_t bin[MD5_DIGEST_SIZE];
	md5_digest(&ctx, MD5_DIGEST_SIZE, bin);
	uint8_t hex[BASE16_ENCODE_LENGTH(MD5_DIGEST_SIZE)];
	base16_encode_update(hex, MD5_DIGEST_SIZE, bin);
	return {reinterpret_cast<char const *>(hex), sizeof(hex)};
}

std::string base64_encode (std::string const & s) {
	struct base64_encode_ctx ctx;
	base64_encode_init(&ctx);
	uint8_t b64[BASE64_ENCODE_LENGTH(s.size())];
	auto len = base64_encode_update(&ctx, b64, s.size(), reinterpret_cast<uint8_t const *>(s.data()));
	len += base64_encode_final(&ctx, b64 + len);
	return {reinterpret_cast<char const *>(b64), len};
}

int make_upstream_agent_conn () {
	char const * path;
	int sock;
	struct sockaddr_un addr;

	if (!(path = getenv("SSH_AUTH_SOCK"))) {
		std::clog << "no $SSH_AUTH_SOCK" << std::endl;
		exit(EX_UNAVAILABLE);
	}

	if ((sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1) {
		perror("socket");
		exit(EX_UNAVAILABLE);
	}
	if (fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC)) {
		perror("fcntl");
		exit(EX_UNAVAILABLE);
	}
	
	addr.sun_family = AF_UNIX;
	
	if (strlen(path) >= sizeof(addr.sun_path)) {
		std::clog << "$SSH_AUTH_SOCK too long" << std::endl;
		exit(EX_UNAVAILABLE);
	}

	strcpy(addr.sun_path, path);

	if (connect(sock, reinterpret_cast<struct sockaddr const *>(&addr), sizeof(addr))) {
		perror("connect");
		exit(EX_UNAVAILABLE);
	}

	return sock;
}

int make_listen_sock () {
	int sock;
	struct sockaddr_un addr;
	
	if ((sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1) {
		perror("socket");
		exit(EX_UNAVAILABLE);
	}
	if (fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC)) {
		perror("fcntl");
		exit(EX_UNAVAILABLE);
	}

	addr.sun_family = AF_UNIX;
	
	if (path.native().length() >= sizeof(addr.sun_path)) {
		std::clog << "path for listen socket too long" << std::endl;
		exit(EX_UNAVAILABLE);
	}

	strcpy(addr.sun_path, path.c_str());

	if (bind(sock, reinterpret_cast<struct sockaddr const *>(&addr), sizeof(addr))) {
		perror("bind");
		exit(EX_UNAVAILABLE);
	}
	
	if (listen(sock, 0)) {
		perror("listen");
		exit(EX_UNAVAILABLE);
	}

	return sock;
}

void parse_cmdline (int const argc, char const * const * const argv) {
	po::options_description opts{"OPTIONS"};
	opts.add_options()
		("all-confirmed,A",		po::bool_switch(&all_confirmed),"allow all other keys with confirmation")
		("comment,c",			po::value(&allowed_comment),	"key specified by comment")
		("comment-confirmed,C",		po::value(&confirmed_comment),	"key specified by comment, with confirmation")
		("debug,d",			po::bool_switch(&debug),	"show some debug info, don't fork")
		("fingerprint,fp,f",		po::value(&allowed_md5),	"key specified by pubkey's hex-encoded md5 fingerprint")
		("fingerprint-confirmed,F",	po::value(&confirmed_md5),	"key specified by pubkey's hex-encoded md5 fingerprint, with confirmation")
		("help,h",			"print this help message")
		("key,k",			po::value(&allowed_b64),	"key specified by base64-encoded pubkey")
		("key-confirmed,K",		po::value(&confirmed_b64),	"key specified by base64-encoded pubkey, with confirmation")
		("name,n",			po::value(&saf_name),		"name for this instance of ssh-agent-filter, for confirmation puposes")
		("version,V",			"print version information")
		;
	po::variables_map config;
	store(parse_command_line(argc, argv, opts), config);
	notify(config);
	
	if (config.count("help")) {
		std::cout << "Invocation: ssh-agent-filter [ OPTIONS ]" << std::endl;
		std::cout << opts << std::endl;
		exit(EX_OK);
	}
	
	if (config.count("version")) {
		std::cout << SSH_AGENT_FILTER_VERSION << std::endl;
		exit(EX_OK);
	}

	// canonicalize hashes
	for (auto & s : allowed_md5)
		for (auto it = s.begin(); it != s.end(); )
			if (isxdigit(*it)) {
				*it = tolower(*it);
				++it;
			} else
				it = s.erase(it);
}

void setup_filters () {
	io::stream_buffer<io::file_descriptor> agent_filebuf{make_upstream_agent_conn(), io::close_handle};
	std::iostream agent{&agent_filebuf};
	agent.exceptions(std::ios::badbit | std::ios::failbit);
	
	agent << rfc4251string{std::string{SSH2_AGENTC_REQUEST_IDENTITIES}};
	rfc4251string answer;
	agent >> answer;
	std::istringstream answer_iss{answer};
	answer_iss.exceptions(std::ios::badbit | std::ios::failbit);
	rfc4251byte resp_code;
	answer_iss >> resp_code;
	if (resp_code != SSH2_AGENT_IDENTITIES_ANSWER)
		throw std::runtime_error{"unexpected answer from ssh-agent"};
	rfc4251uint32 keycount;
	answer_iss >> keycount;
	for (uint32_t i = keycount; i; --i) {
		rfc4251string key;
		rfc4251string comment;
		answer_iss >> key >> comment;
		
		auto b64 = base64_encode(key);
		if (debug) std::clog << b64 << std::endl;
		
		auto md5 = md5_hex(key);
		if (debug) std::clog << md5 << std::endl;
		
		std::string comm(comment);
		if (debug) std::clog << comm << std::endl;
		
		bool allow{false};

		if (std::count(allowed_b64.begin(), allowed_b64.end(), b64)) {
			allow = true;
			if (debug) std::clog << "key allowed by equal base64 representation" << std::endl;
		}
		if (std::count(allowed_md5.begin(), allowed_md5.end(), md5)) {
			allow = true;
			if (debug) std::clog << "key allowed by matching md5 fingerprint" << std::endl;
		}
		if (std::count(allowed_comment.begin(), allowed_comment.end(), comm)) {
			allow = true;
			if (debug) std::clog << "key allowed by matching comment" << std::endl;
		}
		
		if (allow) allowed_pubkeys.emplace(std::move(key));
		else {
			bool confirm{false};
			
			if (std::count(confirmed_b64.begin(), confirmed_b64.end(), b64)) {
				confirm = true;
				if (debug) std::clog << "key allowed with confirmation by equal base64 representation" << std::endl;
			}
			if (std::count(confirmed_md5.begin(), confirmed_md5.end(), md5)) {
				confirm = true;
				if (debug) std::clog << "key allowed with confirmation by matching md5 fingerprint" << std::endl;
			}
			if (std::count(confirmed_comment.begin(), confirmed_comment.end(), comm)) {
				confirm = true;
				if (debug) std::clog << "key allowed with confirmation by matching comment" << std::endl;
			}
			if (all_confirmed) {
				confirm = true;
				if (debug) std::clog << "key allowed with confirmation by catch-all (-A)" << std::endl;
			}
			
			if (confirm) confirmed_pubkeys.emplace(std::move(key), std::move(comm));
		}

		if (debug) std::clog << std::endl;
	}
}

bool confirm (std::string const & question) {
	char const * sap;
	if (!(sap = getenv("SSH_ASKPASS")))
		sap = "ssh-askpass";
	pid_t pid = fork();
	if (pid < 0)
		throw std::runtime_error("fork()");
	if (pid == 0) {
		// child
		char const * args[3] = { sap, question.c_str(), nullptr };
		// see execvp(3p) for cast rationale
		execvp(sap, const_cast<char * const *>(args));
		perror("exec");
		exit(EX_UNAVAILABLE);
	} else {
		// parent
		int status;
		return waitpid(pid, &status, 0) > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
	}
}

void notify (std::string action, std::string description, std::string saf_name, std::string key_name)
{
	char const * notifyhelper;
	if (!(notifyhelper = getenv("SSH_AGENT_FILTER_NOTIFY_HELPER")))
		notifyhelper = "/usr/lib/ssh-agent-filter/notifyhelper";

	pid_t pid = fork();
	if (pid < 0)
		throw std::runtime_error("fork()");
	if (pid != 0) { waitpid(pid, NULL, 0); return;} /* this is fire-and-forget */

	if (fork()) _exit(0); /* now the parent can wait and cleanup gets done and children can die */

	execlp(notifyhelper, notifyhelper, action.c_str(), description.c_str(), saf_name.c_str(), key_name.c_str());
	perror("exec");
	exit(EX_UNAVAILABLE);
}

// Return a plain text description of the request if it results from a
// PAM_SSH_AGENT_AUTH_REQUESTv1 (as created by pam-ssh-agent-auth) or
// accidentally looks like it.
std::string dissect_auth_data_ssh_pam_ssh_agent_auth (rfc4251string const & session_identifier) try {
	std::istringstream idstream{session_identifier};
	idstream.exceptions(std::ios::badbit | std::ios::failbit);

	rfc4251uint32 type; idstream >> type;
	if (type != 101) return ""; // should be PAM_SSH_AGENT_AUTH_REQUESTv1
	rfc4251string cookie, user, ruser, servicename, pwd, action, hostname;
	rfc4251uint64 ts;
	idstream >> cookie >> user >> ruser >> servicename >> pwd >> action >> hostname >> ts;

	std::string singleuser;
	if (std::string{user} == std::string{ruser}) singleuser = std::string{user};
	else singleuser = std::string{user} + " (" + std::string{ruser} + ")";

	// FIXME: this could need real escaping (reverse shell escaping?)
	std::string actionstring = "";
	std::istringstream actionstream{action};
	actionstream.exceptions(std::ios::badbit | std::ios::failbit);
	rfc4251uint32 argc;
	rfc4251string argv;
	actionstream >> argc;
	for (unsigned int i = 0; i < argc; ++i) {
		if (actionstring != "") actionstring += " ";
		actionstream >> argv;
		actionstring += std::string{argv};
	}

	// FIXME: ts is ignored, we could check that and warn if there are big differences.

	return "User " + singleuser + " wants to use " + std::string{servicename} + " in " + std::string{pwd} + " to run " + actionstring + " on " + std::string{hostname} + ".\n";

} catch (...) {
	return "";
}

bool dissect_auth_data_ssh (rfc4251string const & data, std::string & request_description) try {
	std::istringstream datastream{data};
	datastream.exceptions(std::ios::badbit | std::ios::failbit);

	// Format specified in RFC 4252 Section 7
	rfc4251string session_identifier; datastream >> session_identifier;
	rfc4251byte requesttype; datastream >> requesttype;
	rfc4251string username; datastream >> username;
	rfc4251string servicename; datastream >> servicename;
	rfc4251string publickeystring; datastream >> publickeystring;
	rfc4251bool shouldbetrue; datastream >> shouldbetrue;
	rfc4251string publickeyalgorithm; datastream >> publickeyalgorithm;
	rfc4251string publickey; datastream >> publickey;

	request_description = "The request is for an ssh connection as user '" + std::string{username} + "' with service name '" + std::string{servicename} + "'.\n";

	std::string additional = dissect_auth_data_ssh_pam_ssh_agent_auth(session_identifier);

	if (additional != "")
		request_description += additional;

	return true;
} catch (...) {
	return false;
}

rfc4251string handle_request (rfc4251string const & r) {
	std::istringstream request{r};
	std::ostringstream answer;
	request.exceptions(std::ios::badbit | std::ios::failbit);
	answer.exceptions(std::ios::badbit | std::ios::failbit);
	rfc4251byte request_code;
	request >> request_code;
	switch (request_code) {
		case SSH2_AGENTC_REQUEST_IDENTITIES:
			{
				io::stream_buffer<io::file_descriptor> agent_filebuf{make_upstream_agent_conn(), io::close_handle};
				std::iostream agent{&agent_filebuf};
				agent.exceptions(std::ios::badbit | std::ios::failbit);
				rfc4251string agent_answer;
				agent << rfc4251string{std::string{SSH2_AGENTC_REQUEST_IDENTITIES}};
				agent >> agent_answer;
				// temp to test key filtering when signing
				//return agent_answer;
				std::istringstream agent_answer_iss{agent_answer};
				agent_answer_iss.exceptions(std::ios::badbit | std::ios::failbit);
				rfc4251byte answer_code;
				rfc4251uint32 keycount;
				agent_answer_iss >> answer_code >> keycount;
				if (answer_code != SSH2_AGENT_IDENTITIES_ANSWER)
					throw std::runtime_error{"unexpected answer from ssh-agent"};
				std::vector<std::pair<rfc4251string, rfc4251string>> keys;
				for (uint32_t i = keycount; i; --i) {
					rfc4251string key;
					rfc4251string comment;
					agent_answer_iss >> key >> comment;
					if (allowed_pubkeys.count(key) or confirmed_pubkeys.count(key))
						keys.emplace_back(std::move(key), std::move(comment));
				}
				answer << answer_code << rfc4251uint32{static_cast<uint32_t>(keys.size())};
				for (auto const & k : keys)
					answer << k.first << k.second;
			}
			break;
		case SSH2_AGENTC_SIGN_REQUEST:
			{
				rfc4251string key;
				rfc4251string data;
				rfc4251uint32 flags;
				request >> key >> data >> flags;
				bool allow{false};

				std::string request_description;
				auto it = confirmed_pubkeys.find(key);
				
				if (allowed_pubkeys.count(key))
					allow = true;
				else {
					if (it != confirmed_pubkeys.end()) {
						bool dissect_ok{false};
						if (!dissect_ok)
							dissect_ok = dissect_auth_data_ssh(data, request_description);
						if (!dissect_ok)
							request_description = "The request format is unknown.";
						
						std::string question = "Something behind the ssh-agent-filter";
						if (saf_name.length())
							question += " named '" + saf_name + "'";
						question += " requested use of the key named '" + it->second + "'.\n";
						question += request_description;
						allow = confirm(question);
					}
				}
				
				if (allow) {
					io::stream_buffer<io::file_descriptor> agent_filebuf{make_upstream_agent_conn(), io::close_handle};
					std::iostream agent{&agent_filebuf};
					agent.exceptions(std::ios::badbit | std::ios::failbit);
					rfc4251string agent_answer;
					
					agent << r;
					agent >> agent_answer;

					if (true) {
						std::istringstream agent_answer_iss{agent_answer};
						agent_answer_iss.exceptions(std::ios::badbit | std::ios::failbit);
						rfc4251byte response;
						agent_answer_iss >> response;

						/** @todo shove around the question generation, and find key names even for unconfirmed keys. so far, only the declarations for it and request_description have been moved to scope. */
						notify(response == SSH2_AGENT_SIGN_RESPONSE ? "agent-granted" : "agent-denied", request_description, saf_name, it != confirmed_pubkeys.end() ? it->second : "a key that's not in the confirm list");
					}

					return agent_answer;
				} else
					answer << rfc4251byte{SSH_AGENT_FAILURE};
			}
			break;
		case SSH_AGENTC_REQUEST_RSA_IDENTITIES:
			answer << rfc4251byte{SSH_AGENT_RSA_IDENTITIES_ANSWER};
			// we got no SSHv1 keys
			answer << rfc4251uint32{0};
			break;
		case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
			answer << rfc4251byte{SSH_AGENT_SUCCESS};
			break;
		case SSH_AGENTC_RSA_CHALLENGE:
		case SSH_AGENTC_ADD_RSA_IDENTITY:
		case SSH_AGENTC_REMOVE_RSA_IDENTITY:
		case SSH_AGENTC_ADD_RSA_ID_CONSTRAINED:
		case SSH2_AGENTC_ADD_IDENTITY:
		case SSH2_AGENTC_REMOVE_IDENTITY:
		case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		case SSH2_AGENTC_ADD_ID_CONSTRAINED:
		case SSH_AGENTC_ADD_SMARTCARD_KEY:
		case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		case SSH_AGENTC_LOCK:
		case SSH_AGENTC_UNLOCK:
		case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
		default:
			answer << rfc4251byte{SSH_AGENT_FAILURE};
			break;
	}

	return rfc4251string{answer.str()};
}

void handle_client (int const sock) try {
	io::stream_buffer<io::file_descriptor> client_filebuf{sock, io::close_handle};
	std::iostream client{&client_filebuf};
	client.exceptions(std::ios::badbit | std::ios::failbit);
	
	for (;;) {
		rfc4251string request;
		client >> request;
		client << handle_request(request) << std::flush;
	}
} catch (...) {
}

void sighandler (int sig) {
	switch (sig) {
		case SIGPIPE:
			break;
		default:
			remove(path);
			std::abort();
	}
}

int main (int const argc, char const * const * const argv) {
	parse_cmdline(argc, argv);
	
	setup_filters();

	path = fs::current_path() / ("agent." + std::to_string(getpid()));
	int listen_sock = make_listen_sock();

	if (not debug) {
		pid_t pid = fork();
		if (pid == -1) {
			perror("fork");
			exit(EX_OSERR);
		}
		if (pid > 0) {
			std::cout << "SSH_AUTH_SOCK='" << path.native() << "'; export SSH_AUTH_SOCK;" << std::endl;
			std::cout << "SSH_AGENT_PID='" << pid << "'; export SSH_AGENT_PID;" << std::endl;
			std::cout << "echo 'Agent pid " << pid << "';" << std::endl;
			exit(EX_OK);
		}
	
		setsid();
		chdir("/");
		int devnull = open("/dev/null", O_RDWR);
		dup2(devnull, 0);
		dup2(devnull, 1);
		dup2(devnull, 2);
		close(devnull);
	} else {
		std::cout << "copy this to another terminal:" << std::endl;
		std::cout << "SSH_AUTH_SOCK='" << path.native() << "'; export SSH_AUTH_SOCK;" << std::endl;
	}
	
	signal(SIGINT, sighandler);
	signal(SIGPIPE, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGTERM, sighandler);

	int client_sock;
	while ((client_sock = accept(listen_sock, nullptr, nullptr)) != -1) {
		std::thread t{handle_client, client_sock};
		t.detach();
	}
}
