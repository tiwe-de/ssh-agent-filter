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

#include <string>
#include <vector>
#include <set>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <ext/stdio_filebuf.h>

#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sysexits.h>
#include <nettle/md5.h>
#include <nettle/base64.h>
#include <nettle/base16.h>

#include "rfc4251.h"
#include "ssh-agent.h"
#include "version.h"


std::vector<std::string> allowed_b64;
std::vector<std::string> allowed_md5;
std::vector<std::string> allowed_comment;
std::set<rfc4251string> allowed_pubkeys;
bool debug{false};
fs::path path;


std::string md5_hex (std::string const & s) {
	struct md5_ctx ctx;
	md5_init(&ctx);
	md5_update(&ctx, s.size(), reinterpret_cast<uint8_t const *>(s.data()));
	uint8_t bin[MD5_DIGEST_SIZE];
	md5_digest(&ctx, MD5_DIGEST_SIZE, bin);
	uint8_t hex[BASE16_ENCODE_LENGTH(MD5_DIGEST_SIZE)];
	base16_encode_update(hex, MD5_DIGEST_SIZE, bin);
	return std::string(reinterpret_cast<char const *>(hex), sizeof(hex));
}

std::string base64_encode (std::string const & s) {
	struct base64_encode_ctx ctx;
	base64_encode_init(&ctx);
	uint8_t b64[BASE64_ENCODE_LENGTH(s.size())];
	auto len = base64_encode_update(&ctx, b64, s.size(), reinterpret_cast<uint8_t const *>(s.data()));
	len += base64_encode_final(&ctx, b64 + len);
	return std::string(reinterpret_cast<char const *>(b64), len);
}

int make_upstream_agent_conn () {
	char const * path;
	int sock;
	struct sockaddr_un addr;

	if (!(path = getenv("SSH_AUTH_SOCK"))) {
		std::clog << "no $SSH_AUTH_SOCK" << std::endl;
		exit(EX_UNAVAILABLE);
	}

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
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
	
	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
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
	po::options_description opts("OPTIONS");
	opts.add_options()
		("comment,c",		po::value(&allowed_comment),	"key specified by comment")
		("debug,d",		po::bool_switch(&debug),	"show some debug info, don't fork")
		("fingerprint,fp,f",	po::value(&allowed_md5),	"key specified by pubkey's hex-encoded md5 fingerprint")
		("help,h",		"print this help message")
		("key,k",		po::value(&allowed_b64),	"key specified by base64-encoded pubkey")
		("version,V",		"print version information")
		;
	po::variables_map config;
	po::store(po::parse_command_line(argc, argv, opts), config);
	po::notify(config);
	
	if (config.count("help")) {
		std::cout << "Invocation: ssh-agent-filter [ OPTIONS ] -- [ SSH ARGUMENTS ]" << std::endl;
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
	__gnu_cxx::stdio_filebuf<char> agent_filebuf(make_upstream_agent_conn(), std::ios::in | std::ios::out);
	std::iostream agent(&agent_filebuf);
	agent.exceptions(std::ios::badbit | std::ios::failbit);
	
	agent << rfc4251string(std::string(1, SSH2_AGENTC_REQUEST_IDENTITIES));
	rfc4251string answer;
	agent >> answer;
	std::istringstream answer_iss(answer);
	answer_iss.exceptions(std::ios::badbit | std::ios::failbit);
	rfc4251byte resp_code;
	answer_iss >> resp_code;
	if (resp_code != SSH2_AGENT_IDENTITIES_ANSWER)
		throw std::runtime_error("unexpected answer from ssh-agent");
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
		
		if (std::count(allowed_b64.begin(), allowed_b64.end(), b64)) {
			allowed_pubkeys.insert(key);
			if (debug) std::clog << "key allowed by equal base64 representation" << std::endl;
		}
		if (std::count(allowed_md5.begin(), allowed_md5.end(), md5)) {
			allowed_pubkeys.insert(key);
			if (debug) std::clog << "key allowed by matching md5 fingerprint" << std::endl;
		}
		if (std::count(allowed_comment.begin(), allowed_comment.end(), comm)) {
			allowed_pubkeys.insert(key);
			if (debug) std::clog << "key allowed by matching comment" << std::endl;
		}
		
		if (debug) std::clog << std::endl;
	}
}

rfc4251string handle_request (rfc4251string const & r) {
	std::istringstream request(r);
	std::ostringstream answer;
	request.exceptions(std::ios::badbit | std::ios::failbit);
	answer.exceptions(std::ios::badbit | std::ios::failbit);
	rfc4251byte request_code;
	request >> request_code;
	switch (request_code) {
		case SSH2_AGENTC_REQUEST_IDENTITIES:
			{
				__gnu_cxx::stdio_filebuf<char> agent_filebuf(make_upstream_agent_conn(), std::ios::in | std::ios::out);
				std::iostream agent(&agent_filebuf);
				agent.exceptions(std::ios::badbit | std::ios::failbit);
				rfc4251string agent_answer;
				agent << rfc4251string(std::string(1, SSH2_AGENTC_REQUEST_IDENTITIES));
				agent >> agent_answer;
				// temp to test key filtering when signing
				//return agent_answer;
				std::istringstream agent_answer_iss(agent_answer);
				rfc4251byte answer_code;
				rfc4251uint32 keycount;
				agent_answer_iss >> answer_code >> keycount;
				if (answer_code != SSH2_AGENT_IDENTITIES_ANSWER)
					throw std::runtime_error("unexpected answer from ssh-agent");
				std::vector<std::pair<rfc4251string, rfc4251string>> keys;
				for (uint32_t i = keycount; i; --i) {
					rfc4251string key;
					rfc4251string comment;
					agent_answer_iss >> key >> comment;
					if (allowed_pubkeys.count(key))
						keys.emplace_back(std::move(key), std::move(comment));
				}
				answer << answer_code << rfc4251uint32(keys.size());
				for (auto const & k : keys)
					answer << k.first << k.second;
			}
			break;
		case SSH2_AGENTC_SIGN_REQUEST:
			{
				rfc4251string key;
				request >> key;
				if (allowed_pubkeys.count(key)) {
					__gnu_cxx::stdio_filebuf<char> agent_filebuf(make_upstream_agent_conn(), std::ios::in | std::ios::out);
					std::iostream agent(&agent_filebuf);
					agent.exceptions(std::ios::badbit | std::ios::failbit);
					rfc4251string agent_answer;
					
					agent << r;
					agent >> agent_answer;
					return agent_answer;
				} else
					answer << rfc4251byte(SSH_AGENT_FAILURE);
			}
			break;
		case SSH_AGENTC_REQUEST_RSA_IDENTITIES:
			answer << rfc4251byte(SSH_AGENT_RSA_IDENTITIES_ANSWER);
			// we got no SSHv1 keys
			answer << rfc4251uint32(0);
			break;
		case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
			answer << rfc4251byte(SSH_AGENT_SUCCESS);
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
			answer << rfc4251byte(SSH_AGENT_FAILURE);
			break;
	}

	return rfc4251string(answer.str());
}

void handle_client (int const sock) {
	// we could use only one streambuf and iostream but when
	// switching from read to write an lseek call is made that
	// fails with ESPIPE and causes an exception
	__gnu_cxx::stdio_filebuf<char> client_filebuf_in(sock, std::ios::in);
	__gnu_cxx::stdio_filebuf<char> client_filebuf_out(sock, std::ios::out);
	std::istream client_in(&client_filebuf_in);
	std::ostream client_out(&client_filebuf_out);
	client_out.exceptions(std::ios::badbit | std::ios::failbit);
	
	rfc4251string request;
	while (client_in >> request) try {
		client_out << handle_request(request) << std::flush;
	} catch (...) {
		break;
	}
}

void sighandler (int sig) {
	switch (sig) {
		case SIGINT:
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

		signal(SIGINT, sighandler);
		signal(SIGPIPE, sighandler);
		signal(SIGHUP, sighandler);
		signal(SIGTERM, sighandler);
	}

	int client_sock;
	while ((client_sock = accept(listen_sock, nullptr, nullptr)) != -1) {
		std::thread t(handle_client, client_sock);
		t.detach();
	}
}
