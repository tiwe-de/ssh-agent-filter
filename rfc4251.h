/*
 * rfc4251.h -- implements types from RFC 4251, section 5
 *
 * rfc4251byte		byte
 * rfc4251bool		bool
 * rfc4251uint32	uint32
 * rfc4251uint64	uint64
 * rfc4251string	string, incl. mpint and name-list
 *
 * those structs contain the objects in their RFC 4251 representation,
 * conversions are provided via constructors and cast operators
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

#include <vector>
#include <string>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <arpa/inet.h>	// ntohl() / htonl()
#include <gmpxx.h>
#include <boost/operators.hpp>

struct rfc4251byte {
	union {
		uint8_t value;
		char buf[1];
	};

	rfc4251byte () = default;
	explicit rfc4251byte (uint8_t v) : value(v) {}
	inline explicit rfc4251byte (std::istream &);

	operator uint8_t () const { return value; }
};

inline std::istream & operator>> (std::istream & is, rfc4251byte & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251byte const & x) {
	return os.write(x.buf, sizeof(x.buf));
}

inline rfc4251byte::rfc4251byte (std::istream & is) {
	is >> *this;
}

struct rfc4251bool {
	union {
		bool value;
		char buf[1];
	};

	rfc4251bool () = default;
	explicit rfc4251bool (uint8_t v) : value(v) {}
	inline explicit rfc4251bool (std::istream &);

	operator uint8_t () const { return value; }
};

inline std::istream & operator>> (std::istream & is, rfc4251bool & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251bool const & x) {
	return os.write(x.buf, sizeof(x.buf));
}

inline rfc4251bool::rfc4251bool (std::istream & is) {
	is >> *this;
}

struct rfc4251uint32 {
	union {
		uint32_t value;
		char buf[4];
	};

	rfc4251uint32 () = default;
	explicit rfc4251uint32 (uint32_t v) { value = htonl(v); }
	inline explicit rfc4251uint32 (std::istream &);

	operator uint32_t () const { return ntohl(value); }
};

inline std::istream & operator>> (std::istream & is, rfc4251uint32 & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251uint32 const & x) {
	return os.write(x.buf, sizeof(x.buf));
}

inline rfc4251uint32::rfc4251uint32 (std::istream & is) {
	is >> *this;
}

struct rfc4251uint64 {
	union {
		uint64_t value;
		char buf[8];
	};

	rfc4251uint64 () = default;
	inline explicit rfc4251uint64 (uint64_t v);
	inline explicit rfc4251uint64 (std::istream &);

	inline explicit operator uint64_t () const;
};

inline rfc4251uint64::rfc4251uint64 (uint64_t v) {
	for (int_fast8_t i{7}; i >= 0; --i) {
		buf[i] = v & 0xff;
		v >>= 8;
	}
}

inline rfc4251uint64::operator uint64_t () const {
	uint64_t ret{0};
	for (uint_fast8_t i{0}; i < 8; ++i) {
		ret |= buf[i];
		ret <<= 8;
	}
	return ret;
}

inline std::istream & operator>> (std::istream & is, rfc4251uint64 & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251uint64 const & x) {
	return os.write(x.buf, sizeof(x.buf));
}

inline rfc4251uint64::rfc4251uint64 (std::istream & is) {
	is >> *this;
}

struct rfc4251string : boost::totally_ordered<rfc4251string> {
	std::vector<char> value;
	
	rfc4251string () = default;
	inline explicit rfc4251string (char const *, size_t);
	explicit rfc4251string (std::string const & s) : rfc4251string{s.data(), s.size()} {}
	explicit rfc4251string (std::vector<std::string> const &);
	explicit rfc4251string (mpz_srcptr);
	explicit rfc4251string (mpz_class const & x) : rfc4251string{x.get_mpz_t()} {}
	inline explicit rfc4251string (std::istream &);

	size_t size () const { return value.size(); }
	char const * data () const { return value.data(); }
	char * data () { return value.data(); }

	operator std::string () const { return {value.begin(), value.end()}; }
	operator std::vector<std::string> () const;
	operator mpz_class () const;
};

inline rfc4251string::rfc4251string (char const * s, size_t l) {
	if (l > std::numeric_limits<uint32_t>::max())
		throw std::length_error{"32-bit limit for rfc4251string exceeded"};
	value.insert(value.end(), s, s + l);
}

inline std::istream & operator>> (std::istream & is, rfc4251string & s) {
	s.value.clear();
	rfc4251uint32 len;
	if (is >> len) {
		s.value.resize(len);
		is.read(s.value.data(), len);
	}
	return is;
}

inline std::ostream & operator<< (std::ostream & os, rfc4251string const & s) {
	if (s.value.size() > std::numeric_limits<uint32_t>::max())
		throw std::length_error{"32-bit limit for rfc4251string exceeded"};
	if (os << rfc4251uint32{static_cast<uint32_t>(s.value.size())})
		os.write(s.value.data(), s.value.size());
	return os;
}

inline rfc4251string::rfc4251string (std::istream & is) {
	is >> *this;
}

inline bool operator== (rfc4251string const & l, rfc4251string const & r) {
	return l.value == r.value;
}

inline bool operator< (rfc4251string const & l, rfc4251string const & r) {
	return l.value < r.value;
}
