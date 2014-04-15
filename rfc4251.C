#include "rfc4251.h"

rfc4251string::rfc4251string (std::vector<std::string> const & v) {
	for (auto it = v.begin(); it != v.end();) {
		if (it->size() == 0)
			throw std::length_error{"name of zero length"};
		if (value.size() + it->size() > std::numeric_limits<uint32_t>::max())
			throw std::length_error{"32-bit limit for rfc4251string exceeded"};
		value.insert(value.end(), it->data(), it->data() + it->size());
		++it;
		if (it == v.end())
			break;
		value.push_back(',');
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
