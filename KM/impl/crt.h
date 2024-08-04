namespace crt
{
	template <typename t>
	__forceinline int strlen(t str) {
		if (!str)
		{
			return 0;
		}

		t buffer = str;

		while (*buffer)
		{
			*buffer++;
		}

		return (int)(buffer - str);
	}

	bool strcmp(const char* src, const char* dst)
	{
		if (!src || !dst)
		{
			return true;
		}

		const auto src_sz = crt::strlen(src);
		const auto dst_sz = crt::strlen(dst);

		if (src_sz != dst_sz)
		{
			return true;
		}

		for (int i = 0; i < src_sz; i++)
		{
			if (src[i] != dst[i])
			{
				return true;
			}
		}

		return false;
	}
}

