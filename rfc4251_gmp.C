/*
 * rfc4251_gmp.C -- implements mpint/gmp conversions for rfc4251::string
 *
 * these functions need linking against libgmp
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

#include "rfc4251.H"

namespace rfc4251 {

string::string (mpz_srcptr x) {
	if (mpz_sgn(x) == 0)
		return;

	auto const import_positive = [] (mpz_srcptr x, std::vector<char> & value) {
		size_t bits{mpz_sizeinbase(x, 2)};
		size_t bytes{(bits + 7) / 8};
		size_t extrabyte{(bits % 8) == 0}; // need extra byte if MSB is 1 to keep it non-negative
		if (bytes + extrabyte > std::numeric_limits<uint32_t>::max())
			throw std::length_error{"32-bit limit for rfc4251::string exceeded"};
		value.resize(bytes + extrabyte);
		value[0] = 0;
		mpz_export(value.data() + extrabyte, nullptr, 1, 1, 1, 0, x);
	};
	if (mpz_sgn(x) == 1)
		import_positive(x, value);
	else {
		// handle two's complement: add 1, invert all bits
		mpz_class tmp{x};
		tmp += 1;
		import_positive(tmp.get_mpz_t(), value);
		for (auto & i : value)
			i ^= 0xff;
	}
}

string::operator mpz_class () const {
	mpz_class ret;
	mpz_import(ret.get_mpz_t(), value.size(), 1, 1, 1, 0, value.data());
	if (mpz_sizeinbase(ret.get_mpz_t(), 2) == value.size() * 8) { // negative
		mpz_com(ret.get_mpz_t(), ret.get_mpz_t());
		ret += 1;
		mpz_neg(ret.get_mpz_t(), ret.get_mpz_t());
	}
	return ret;
}

}
