/*
 * rfc4251.C -- support for name-list type from RFC 4251, section 5
 *
 * These are the conversions between an rfc4251::string containing a name-list
 * and vector<string>.
 *
 * Copyright (C) 2013,2015 Timo Weingärtner <timo@tiwe.de>
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

string::string (std::vector<std::string> const & v) {
	for (auto it = v.begin(); it != v.end();) {
		if (it->size() == 0)
			throw std::length_error{"name of zero length"};
		if (value.size() + it->size() > std::numeric_limits<uint32_t>::max())
			throw std::length_error{"32-bit limit for rfc4251::string exceeded"};
		value.insert(value.end(), it->data(), it->data() + it->size());
		++it;
		if (it == v.end())
			break;
		value.push_back(',');
	}
}

string::operator std::vector<std::string> () const {
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

}
