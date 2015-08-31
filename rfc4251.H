/*
 * rfc4251.h -- implements types from RFC 4251, section 5
 *
 * rfc4251::byte	byte
 * rfc4251::boolean	boolean
 * rfc4251::uint32	uint32
 * rfc4251::uint64	uint64
 * rfc4251::string	string, incl. mpint and name-list
 *
 * those structs contain the objects in their RFC 4251 representation,
 * conversions are provided via constructors and cast operators
 *
 * Copyright (C) 2013-2014 Timo Weingärtner <timo@tiwe.de>
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

namespace rfc4251 {

struct byte {
	union {
		uint8_t value;
		char buf[1];
	};

	byte () = default;
	explicit byte (uint8_t v) : value(v) {}
	inline explicit byte (std::istream &);

	operator uint8_t () const { return value; }
};

inline std::istream & operator>> (std::istream & is, byte & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, byte const & x) {
	return os.write(x.buf, sizeof(x.buf));
}

inline byte::byte (std::istream & is) {
	is >> *this;
}

struct boolean {
	union {
		bool value;
		char buf[1];
	};

	boolean () = default;
	explicit boolean (uint8_t v) : value(v) {}
	inline explicit boolean (std::istream &);

	operator uint8_t () const { return value; }
};

inline std::istream & operator>> (std::istream & is, boolean & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, boolean const & x) {
	return os.write(x.buf, sizeof(x.buf));
}

inline boolean::boolean (std::istream & is) {
	is >> *this;
}

struct uint32 {
	union {
		uint32_t value;
		char buf[4];
	};

	uint32 () = default;
	explicit uint32 (uint32_t v) { value = htonl(v); }
	inline explicit uint32 (std::istream &);

	operator uint32_t () const { return ntohl(value); }
};

inline std::istream & operator>> (std::istream & is, uint32 & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, uint32 const & x) {
	return os.write(x.buf, sizeof(x.buf));
}

inline uint32::uint32 (std::istream & is) {
	is >> *this;
}

struct uint64 {
	union {
		uint64_t value;
		char buf[8];
	};

	uint64 () = default;
	inline explicit uint64 (uint64_t v);
	inline explicit uint64 (std::istream &);

	inline explicit operator uint64_t () const;
};

inline uint64::uint64 (uint64_t v) {
	for (int_fast8_t i{7}; i >= 0; --i) {
		buf[i] = v & 0xff;
		v >>= 8;
	}
}

inline uint64::operator uint64_t () const {
	uint64_t ret{0};
	for (uint_fast8_t i{0}; i < 8; ++i) {
		ret <<= 8;
		ret |= static_cast<uint8_t>(buf[i]);
	}
	return ret;
}

inline std::istream & operator>> (std::istream & is, uint64 & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, uint64 const & x) {
	return os.write(x.buf, sizeof(x.buf));
}

inline uint64::uint64 (std::istream & is) {
	is >> *this;
}

struct string : boost::totally_ordered<string> {
	std::vector<char> value;
	
	string () = default;
	inline explicit string (char const *, size_t);
	explicit string (std::string const & s) : string{s.data(), s.size()} {}
	explicit string (std::vector<std::string> const &);
	explicit string (mpz_srcptr);
	explicit string (mpz_class const & x) : string{x.get_mpz_t()} {}
	inline explicit string (std::istream &);

	size_t size () const { return value.size(); }
	char const * data () const { return value.data(); }
	char * data () { return value.data(); }

	operator std::string () const { return {value.begin(), value.end()}; }
	operator std::vector<std::string> () const;
	operator mpz_class () const;
};

inline string::string (char const * s, size_t l) {
	if (l > std::numeric_limits<uint32_t>::max())
		throw std::length_error{"32-bit limit for rfc4251::string exceeded"};
	value.insert(value.end(), s, s + l);
}

inline std::istream & operator>> (std::istream & is, string & s) {
	s.value.clear();
	uint32 len;
	if (is >> len) {
		s.value.resize(len);
		is.read(s.value.data(), len);
	}
	return is;
}

inline std::ostream & operator<< (std::ostream & os, string const & s) {
	if (s.value.size() > std::numeric_limits<uint32_t>::max())
		throw std::length_error{"32-bit limit for rfc4251::string exceeded"};
	if (os << uint32{static_cast<uint32_t>(s.value.size())})
		os.write(s.value.data(), s.value.size());
	return os;
}

inline string::string (std::istream & is) {
	is >> *this;
}

inline bool operator== (string const & l, string const & r) {
	return l.value == r.value;
}

inline bool operator< (string const & l, string const & r) {
	return l.value < r.value;
}

}
