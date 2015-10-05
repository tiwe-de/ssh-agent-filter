/*
 * ssh-agent-filter.C -- filtering proxy for ssh-agent meant to be forwarded to untrusted servers
 *
 * Copyright (C) 2013-2015 Timo Weingärtner <timo@tiwe.de>
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

#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
namespace io = boost::iostreams;

#include <string>
using std::string;

#include <vector>
using std::vector;

#include <set>
#include <map>
#include <iostream>
using std::cout;
using std::clog;
using std::endl;
using std::flush;

#include <stdexcept>
using std::runtime_error;
using std::length_error;
using std::invalid_argument;

#include <system_error>
using std::system_error;
using std::system_category;

#include <utility>
using std::pair;

#include <algorithm>

#include <thread>
#include <mutex>
using std::mutex;
using std::lock_guard;

#include <chrono>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <nettle/md5.h>
#include <nettle/base64.h>
#include <nettle/base16.h>

#include "rfc4251.H"
#include "ssh-agent.h"
#include "version.h"

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

vector<string> allowed_b64;
vector<string> allowed_md5;
vector<string> allowed_comment;
vector<string> confirmed_b64;
vector<string> confirmed_md5;
vector<string> confirmed_comment;
std::set<rfc4251::string> allowed_pubkeys;
std::map<rfc4251::string, string> confirmed_pubkeys;
bool debug{false};
bool all_confirmed{false};
string saf_name;
fs::path path;
mutex fd_fork_mutex;


string md5_hex (string const & s) {
	struct md5_ctx ctx;
	md5_init(&ctx);
	md5_update(&ctx, s.size(), reinterpret_cast<uint8_t const *>(s.data()));
	uint8_t bin[MD5_DIGEST_SIZE];
	md5_digest(&ctx, MD5_DIGEST_SIZE, bin);
	uint8_t hex[BASE16_ENCODE_LENGTH(MD5_DIGEST_SIZE)];
	base16_encode_update(hex, MD5_DIGEST_SIZE, bin);
	return {reinterpret_cast<char const *>(hex), sizeof(hex)};
}

string base64_encode (string const & s) {
	struct base64_encode_ctx ctx;
	base64_encode_init(&ctx);
	uint8_t b64[BASE64_ENCODE_LENGTH(s.size())];
	auto len = base64_encode_update(&ctx, b64, s.size(), reinterpret_cast<uint8_t const *>(s.data()));
	len += base64_encode_final(&ctx, b64 + len);
	return {reinterpret_cast<char const *>(b64), len};
}

void cloexec (int fd) {
	if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC))
		throw system_error(errno, system_category(), "fcntl");
}

void arm(std::ios & stream) {
	stream.exceptions(stream.badbit | stream.failbit);
}

int make_upstream_agent_conn () {
	char const * path;
	int sock;
	struct sockaddr_un addr;

	if (!(path = getenv("SSH_AUTH_SOCK")))
		throw invalid_argument("no $SSH_AUTH_SOCK");

	{
		lock_guard<mutex> lock{fd_fork_mutex};
		if ((sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
			throw system_error(errno, system_category(), "socket");
		cloexec(sock);
	}
	
	addr.sun_family = AF_UNIX;
	
	if (strlen(path) >= sizeof(addr.sun_path))
		throw length_error("$SSH_AUTH_SOCK too long");

	strcpy(addr.sun_path, path);

	if (connect(sock, reinterpret_cast<struct sockaddr const *>(&addr), sizeof(addr)))
		throw system_error(errno, system_category(), "connect");

	return sock;
}

int make_listen_sock () {
	int sock;
	struct sockaddr_un addr;
	
	{
		lock_guard<mutex> lock{fd_fork_mutex};
		if ((sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
			throw system_error(errno, system_category(), "socket");
		cloexec(sock);
	}

	if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK))
		throw system_error(errno, system_category(), "fcntl");

	addr.sun_family = AF_UNIX;
	
	if (path.native().length() >= sizeof(addr.sun_path))
		throw length_error("path for listen socket too long");

	strcpy(addr.sun_path, path.c_str());

	if (bind(sock, reinterpret_cast<struct sockaddr const *>(&addr), sizeof(addr)))
		throw system_error(errno, system_category(), "bind");
	
	if (listen(sock, 0))
		throw system_error(errno, system_category(), "listen");

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
		cout << "Usage: ssh-agent-filter [ OPTIONS ]" << endl;
		cout << opts << endl;
		exit(EX_OK);
	}
	
	if (config.count("version")) {
		cout << SSH_AGENT_FILTER_VERSION << endl;
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
	io::stream<io::file_descriptor> agent{make_upstream_agent_conn(), io::close_handle};
	arm(agent);
	
	agent << rfc4251::string{string{SSH2_AGENTC_REQUEST_IDENTITIES}};
	rfc4251::string answer{agent};
	io::stream<io::array_source> answer_iss{answer.data(), answer.size()};
	arm(answer_iss);
	rfc4251::byte resp_code{answer_iss};
	if (resp_code != SSH2_AGENT_IDENTITIES_ANSWER)
		throw runtime_error{"unexpected answer from ssh-agent"};
	rfc4251::uint32 keycount{answer_iss};
	for (uint32_t i = keycount; i; --i) {
		rfc4251::string key{answer_iss};
		rfc4251::string comment{answer_iss};
		
		auto b64 = base64_encode(key);
		if (debug) clog << b64 << endl;
		
		auto md5 = md5_hex(key);
		if (debug) clog << md5 << endl;
		
		string comm(comment);
		if (debug) clog << comm << endl;
		
		bool allow{false};

		if (std::count(allowed_b64.begin(), allowed_b64.end(), b64)) {
			allow = true;
			if (debug) clog << "key allowed by equal base64 representation" << endl;
		}
		if (std::count(allowed_md5.begin(), allowed_md5.end(), md5)) {
			allow = true;
			if (debug) clog << "key allowed by matching md5 fingerprint" << endl;
		}
		if (std::count(allowed_comment.begin(), allowed_comment.end(), comm)) {
			allow = true;
			if (debug) clog << "key allowed by matching comment" << endl;
		}
		
		if (allow) allowed_pubkeys.emplace(std::move(key));
		else {
			bool confirm{false};
			
			if (std::count(confirmed_b64.begin(), confirmed_b64.end(), b64)) {
				confirm = true;
				if (debug) clog << "key allowed with confirmation by equal base64 representation" << endl;
			}
			if (std::count(confirmed_md5.begin(), confirmed_md5.end(), md5)) {
				confirm = true;
				if (debug) clog << "key allowed with confirmation by matching md5 fingerprint" << endl;
			}
			if (std::count(confirmed_comment.begin(), confirmed_comment.end(), comm)) {
				confirm = true;
				if (debug) clog << "key allowed with confirmation by matching comment" << endl;
			}
			if (all_confirmed) {
				confirm = true;
				if (debug) clog << "key allowed with confirmation by catch-all (-A)" << endl;
			}
			
			if (confirm) confirmed_pubkeys.emplace(std::move(key), std::move(comm));
		}

		if (debug) clog << endl;
	}
}

bool confirm (string const & question) {
	char const * sap;
	if (!(sap = getenv("SSH_ASKPASS")))
		sap = "ssh-askpass";
	pid_t pid;
	{
		lock_guard<mutex> lock{fd_fork_mutex};
		pid = fork();
	}
	if (pid < 0)
		throw runtime_error("fork()");
	if (pid == 0) {
		// child
		char const * args[3] = { sap, question.c_str(), nullptr };
		// see execvp(3p) for cast rationale
		execvp(sap, const_cast<char * const *>(args));
		throw system_error(errno, system_category(), "exec");
	} else {
		// parent
		int status;
		return waitpid(pid, &status, 0) > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
	}
}

bool dissect_auth_data_ssh (rfc4251::string const & data, string & request_description) try {
	io::stream<io::array_source> datastream{data.data(), data.size()};
	arm(datastream);

	// Format specified in RFC 4252 Section 7
	rfc4251::string		session_identifier{datastream};
	rfc4251::byte		requesttype{datastream};
	rfc4251::string		username{datastream};
	rfc4251::string		servicename{datastream};
	rfc4251::string		publickeystring{datastream};
	rfc4251::boolean	shouldbetrue{datastream};
	rfc4251::string		publickeyalgorithm{datastream};
	rfc4251::string		publickey{datastream};

	request_description = "The request is for an ssh connection as user '" + string{username} + "' with service name '" + string{servicename} + "'.";

	if (string{servicename} == "pam_ssh_agent_auth") try {
		clog << base64_encode(session_identifier) << endl;
		io::stream<io::array_source> idstream{session_identifier.data(), session_identifier.size()};
		arm(idstream);

		rfc4251::uint32	type{idstream};
		if (type == 101) {
			// PAM_SSH_AGENT_AUTH_REQUESTv1
			rfc4251::string	cookie{idstream};
			rfc4251::string	user{idstream};
			rfc4251::string	ruser{idstream};
			rfc4251::string	pam_service{idstream};
			rfc4251::string	pwd{idstream};
			rfc4251::string	action{idstream};
			rfc4251::string	hostname{idstream};
			rfc4251::uint64	timestamp{idstream};

			string singleuser{user};
			if (user != ruser)
				singleuser += " (" + string{ruser} + ")";

			string additional;
			additional += "User '" + singleuser + "' wants to use '" + string{pam_service};
			additional += "' in '" + string{pwd};
			
			io::stream<io::array_source> actionstream{action.data(), action.size()};
			arm(actionstream);
			
			rfc4251::uint32	argc{actionstream};
			
			if (argc) {
				additional += " to run";
				for (uint32_t i = argc; i; --i) {
					rfc4251::string	argv{actionstream};
					additional += ' ' + string{argv};
				}
			}
			
			additional += " on " + string{hostname} + ".\n";
			
			auto now = std::chrono::system_clock::now();
			auto req_time = std::chrono::system_clock::from_time_t(static_cast<uint64_t>(timestamp));
			auto timediff = std::chrono::duration_cast<std::chrono::seconds>(now - req_time).count();
			
			additional += "The request was generated " + std::to_string(timediff) + " seconds ago.\n";
			request_description = move(additional);
		}
	} catch (...) {}
	
	return true;
} catch (...) {
	return false;
}

rfc4251::string handle_request (rfc4251::string const & r) {
	io::stream<io::array_source> request{r.data(), r.size()};
	rfc4251::string ret;
	io::stream<io::back_insert_device<vector<char>>> answer{ret.value};
	arm(request);
	arm(answer);
	rfc4251::byte request_code{request};
	switch (request_code) {
		case SSH2_AGENTC_REQUEST_IDENTITIES:
			{
				io::stream<io::file_descriptor> agent{make_upstream_agent_conn(), io::close_handle};
				arm(agent);
				agent << rfc4251::string{string{SSH2_AGENTC_REQUEST_IDENTITIES}};
				// temp to test key filtering when signing
				//return rfc4251::string{agent};
				rfc4251::string agent_answer{agent};
				io::stream<io::array_source> agent_answer_iss{agent_answer.data(), agent_answer.size()};
				arm(agent_answer_iss);
				rfc4251::byte answer_code{agent_answer_iss};
				rfc4251::uint32 keycount{agent_answer_iss};
				if (answer_code != SSH2_AGENT_IDENTITIES_ANSWER)
					throw runtime_error{"unexpected answer from ssh-agent"};
				vector<pair<rfc4251::string, rfc4251::string>> keys;
				for (uint32_t i = keycount; i; --i) {
					rfc4251::string key{agent_answer_iss};
					rfc4251::string comment{agent_answer_iss};
					if (allowed_pubkeys.count(key) or confirmed_pubkeys.count(key))
						keys.emplace_back(std::move(key), std::move(comment));
				}
				answer << answer_code << rfc4251::uint32{static_cast<uint32_t>(keys.size())};
				for (auto const & k : keys)
					answer << k.first << k.second;
			}
			break;
		case SSH2_AGENTC_SIGN_REQUEST:
			{
				rfc4251::string key{request};
				rfc4251::string data{request};
				rfc4251::uint32 flags{request};
				bool allow{false};
				
				if (allowed_pubkeys.count(key))
					allow = true;
				else {
					auto it = confirmed_pubkeys.find(key);
					if (it != confirmed_pubkeys.end()) {
						string request_description;
						bool dissect_ok{false};
						if (!dissect_ok)
							dissect_ok = dissect_auth_data_ssh(data, request_description);
						if (!dissect_ok)
							request_description = "The request format is unknown.";
						
						string question = "Something behind the ssh-agent-filter";
						if (saf_name.length())
							question += " named '" + saf_name + "'";
						question += " requested use of the key named '" + it->second + "'.\n";
						question += request_description;
						allow = confirm(question);
					}
				}
				
				if (allow) {
					io::stream<io::file_descriptor> agent{make_upstream_agent_conn(), io::close_handle};
					arm(agent);
					rfc4251::string agent_answer;
					
					agent << r;
					return rfc4251::string{agent};
				} else
					answer << rfc4251::byte{SSH_AGENT_FAILURE};
			}
			break;
		case SSH_AGENTC_REQUEST_RSA_IDENTITIES:
			answer << rfc4251::byte{SSH_AGENT_RSA_IDENTITIES_ANSWER};
			// we got no SSHv1 keys
			answer << rfc4251::uint32{0};
			break;
		case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
			answer << rfc4251::byte{SSH_AGENT_SUCCESS};
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
			answer << rfc4251::byte{SSH_AGENT_FAILURE};
			break;
	}

	answer << flush;
	return ret;
}

void handle_client (int const sock) try {
	io::stream<io::file_descriptor> client{sock, io::close_handle};
	arm(client);
	
	for (;;)
		client << handle_request(rfc4251::string{client}) << flush;
} catch (...) {
}

void sighandler (int sig) {
	switch (sig) {
		case SIGPIPE:
			break;
		default:
			remove(path);
			std::exit(0);
	}
}

int main (int const argc, char const * const * const argv) {
	parse_cmdline(argc, argv);
	
	setup_filters();

	path = fs::current_path() / ("agent." + std::to_string(getpid()));
	int listen_sock = make_listen_sock();

	if (not debug) {
		pid_t pid = fork();
		if (pid == -1)
			throw system_error(errno, system_category(), "fork");
		if (pid > 0) {
			cout << "SSH_AUTH_SOCK='" << path.native() << "'; export SSH_AUTH_SOCK;" << endl;
			cout << "SSH_AGENT_PID='" << pid << "'; export SSH_AGENT_PID;" << endl;
			cout << "echo 'Agent pid " << pid << "';" << endl;
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
		cout << "copy this to another terminal:" << endl;
		cout << "SSH_AUTH_SOCK='" << path.native() << "'; export SSH_AUTH_SOCK;" << endl;
	}
	
	signal(SIGINT, sighandler);
	signal(SIGPIPE, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGTERM, sighandler);

	for (;;) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(listen_sock, &fds);
		select(listen_sock + 1, &fds, nullptr, nullptr, nullptr);
		int client_sock;
		{
			lock_guard<mutex> lock{fd_fork_mutex};
			if ((client_sock = accept(listen_sock, nullptr, nullptr)) == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				else
					break;
			}
			cloexec(client_sock);
		}
		std::thread t{handle_client, client_sock};
		t.detach();
	}
}
