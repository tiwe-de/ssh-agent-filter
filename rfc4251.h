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
#include <arpa/inet.h>	// ntohl() / htonl()
#include <gmpxx.h>

struct rfc4251byte {
	union {
		uint8_t value;
		char buf[1];
	};

	rfc4251byte () = default;
	explicit rfc4251byte (uint8_t v) : value(v) {}

	operator uint8_t () const { return value; }
};

inline std::istream & operator>> (std::istream & is, rfc4251byte & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251byte const & x) {
	return os.write(x.buf, sizeof(x.buf));;
}


struct rfc4251bool {
	union {
		bool value;
		char buf[1];
	};

	rfc4251bool () = default;
	explicit rfc4251bool (uint8_t v) : value(v) {}

	operator uint8_t () const { return value; }
};

inline std::istream & operator>> (std::istream & is, rfc4251bool & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251bool const & x) {
	return os.write(x.buf, sizeof(x.buf));;
}


struct rfc4251uint32 {
	union {
		uint32_t value;
		char buf[4];
	};

	rfc4251uint32 () = default;
	explicit rfc4251uint32 (uint32_t v) { value = htonl(v); }

	operator uint32_t () const { return ntohl(value); }
};

inline std::istream & operator>> (std::istream & is, rfc4251uint32 & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251uint32 const & x) {
	return os.write(x.buf, sizeof(x.buf));;
}


struct rfc4251uint64 {
	union {
		uint64_t value;
		char buf[8];
	};

	rfc4251uint64 () = default;
	inline explicit rfc4251uint64 (uint64_t v);

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
	return os.write(x.buf, sizeof(x.buf));;
}


struct rfc4251string {
	std::vector<char> value;
	
	rfc4251string () = default;
	inline explicit rfc4251string (char const *);
	inline explicit rfc4251string (char const *, size_t);
	explicit rfc4251string (std::string const & s) : rfc4251string{s.data(), s.size()} {}
	explicit rfc4251string (std::vector<std::string> const &);
	explicit rfc4251string (mpz_srcptr);
	explicit rfc4251string (mpz_class const & x) : rfc4251string{x.get_mpz_t()} {}

	operator std::string () const { return {value.begin(), value.end()}; }
	operator std::vector<std::string> () const;
	operator mpz_class () const;
};

inline rfc4251string::rfc4251string (char const * s) {
	auto len = ntohl(*reinterpret_cast<uint32_t const *>(s));
	value.insert(value.begin(), s + 4, s + 4 + len);
}

inline rfc4251string::rfc4251string (char const * s, size_t l) {
	if (l > std::numeric_limits<uint32_t>::max())
		throw std::length_error{"32-bit limit for rfc4251string exceeded"};
	value.insert(value.end(), s, s + l);
}

rfc4251string::rfc4251string (std::vector<std::string> const & v) {
	if (v.size()) {
		if (v.begin()->size() > std::numeric_limits<uint32_t>::max())
			throw std::length_error{"32-bit limit for rfc4251string exceeded"};
		value.assign(v.begin()->data(), v.begin()->data() + v.begin()->size());
		for (auto it = v.begin() + 1; it != v.end(); ++it) {
			if (value.size() + 1 + it->size() > std::numeric_limits<uint32_t>::max())
				throw std::length_error{"32-bit limit for rfc4251string exceeded"};
			value.push_back(',');
			value.insert(value.end(), it->data(), it->data() + it->size());
		}
	}
}

rfc4251string::rfc4251string (mpz_srcptr x) {
	if (mpz_sgn(x) == 0) {
	} else if (mpz_sgn(x) == 1) {
		size_t bits{mpz_sizeinbase(x, 2)};
		size_t bytes{(bits + 7) / 8};
		size_t extrabyte{(bits % 8) == 0}; // need extra byte if MSB is 1 to keep it non-negative
		if (bytes + extrabyte > std::numeric_limits<uint32_t>::max())
			throw std::length_error{"32-bit limit for rfc4251string exceeded"};
		value.resize(bytes + extrabyte);
		value[0] = 0;
		mpz_export(value.data() + extrabyte, nullptr, 1, 1, 1, 0, x);
	} else {
		mpz_class tmp{x};
		tmp += 1;
		x = tmp.get_mpz_t();
		size_t bits{mpz_sizeinbase(x, 2)};
		size_t bytes{(bits + 7) / 8};
		size_t extrabyte{(bits % 8) == 0}; // need extra byte if MSB is 1 (0 after ^= below) to keep it negative
		if (bytes + extrabyte > std::numeric_limits<uint32_t>::max())
			throw std::length_error{"32-bit limit for rfc4251string exceeded"};
		value.resize(bytes + extrabyte);
		value[0] = 0;
		mpz_export(value.data() + extrabyte, nullptr, 1, 1, 1, 0, x);
		for (auto & i : value)
			i ^= 0xff;
	}
}

rfc4251string::operator std::vector<std::string> () const {
	std::vector<std::string> ret;
	auto name_start = value.begin();
	if (name_start != value.end())
		for (auto it = name_start; ; ++it) {
			if (it == value.end() or *it == ',') {
				if (it == name_start)
					throw std::length_error{"name of zero length"};
				ret.emplace_back(name_start, it);
				name_start = it + 1;
			}
			if (it == value.end())
				break;
		}
	return ret;
}

rfc4251string::operator mpz_class () const {
	mpz_class ret;
	mpz_import(ret.get_mpz_t(), value.size(), 1, 1, 1, 0, value.data());
	if (mpz_sizeinbase(ret.get_mpz_t(), 2) == value.size() * 8) { // negative
		mpz_com(ret.get_mpz_t(), ret.get_mpz_t());
		ret += 1;
		mpz_neg(ret.get_mpz_t(), ret.get_mpz_t());
	}
	return ret;
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

inline bool operator== (rfc4251string const & l, rfc4251string const & r) {
	return l.value == r.value;
}

inline bool operator< (rfc4251string const & l, rfc4251string const & r) {
	return l.value < r.value;
}
