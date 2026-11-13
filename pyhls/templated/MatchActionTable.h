#ifndef MATCH_ACTION_TABLE_H
#define MATCH_ACTION_TABLE_H

#include "../common/Shared.h"
#include "../header/BaseHeader.h"
#include "../ingress/MemoryInterface.h"

// TS: Table Depth Size, MS: Match-key Size, AS: Action Size
template<int TS, int MS, int AS, MatchActionTableType TABLE_TYPE>
class MatchActionTable {
public:
	MatchActionTable() {}
	~MatchActionTable() {}

	int jenkins_hash(const ap_uint<MS> &key) const {
#pragma HLS INLINE
		unsigned int hash = 0;
		constexpr int bytesize = (MS + 7) / 8;
		L_HASH: for (int i = 0; i < bytesize; i++) {
#pragma HLS UNROLL
#pragma HLS LOOP_TRIPCOUNT max=8
			hash += (i == bytesize - 1) ? key.range(MS-1, i*8).to_uint() : key.range(i*8+7, i*8).to_uint();
			hash += (hash << 10);
			hash ^= (hash >> 6);
		}
		hash += (hash << 3);
		hash ^= (hash >> 11);
		hash += (hash << 15);
		return hash;
	}

	int FNV1a_hash(const ap_uint<MS> &key) const {
#pragma HLS PIPELINE II=1
		constexpr int bytesize = (MS + 7) / 8;
		const ap_uint<bytesize*8> data(key);
		unsigned int hash[bytesize+1];
		hash[0] = 2166136261u;

		for (int i = 0; i < bytesize; i++) {
#pragma HLS UNROLL
			hash[i+1] = (hash[i] ^ data.range(i*8+7, i*8)) * 16777619u;
		}

		return hash[bytesize];
	}

	int hash_function(const ap_uint<MS> &key) const {
#pragma HLS INLINE
		return FNV1a_hash(key) % TS;
	}

	void insert_entry(unsigned int *memPtr, const ap_uint<MS> &key, const ap_uint<AS> &value) {
#pragma HLS INLINE
		int index = hash_function(key);
#if defined(DDR) or defined(HBM)
		MemoryInterface::getInstance().update_entry<TS, MS, AS, TABLE_TYPE>(memPtr, index, LookupEntry<MS, AS>(key, value, true));
#else
		MemoryInterface::getInstance().update_entry<TS, MS, AS, TABLE_TYPE>(lookup, index, LookupEntry<MS, AS>(key, value, true));
#endif
	}

	bool delete_entry(unsigned int *memPtr, const ap_uint<MS> &key, const ap_uint<AS> &value) {
#pragma HLS INLINE
		int index = hash_function(key);
#if defined(DDR) or defined(HBM)
		return MemoryInterface::getInstance().delete_entry<TS, MS, AS, TABLE_TYPE>(memPtr, index, key, value);
#else
		return MemoryInterface::getInstance().delete_entry<TS, MS, AS, TABLE_TYPE>(lookup, index, key, value);
#endif
	}

	bool search_index(const unsigned int *memPtr, const ap_uint<MS> &key, int &index) {
#pragma HLS INLINE
		index = hash_function(key);
#if defined(DDR) or defined(HBM)
		return MemoryInterface::getInstance().search_index<TS, MS, AS, TABLE_TYPE>(memPtr, index, key);
#else
		return MemoryInterface::getInstance().search_index<TS, MS, AS, TABLE_TYPE>(lookup, index, key);
#endif
	}

	bool search_entry(const unsigned int *memPtr, const ap_uint<MS> &key, ap_uint<AS> &value) {
#pragma HLS INLINE
		int index = hash_function(key);
#if defined(DDR) or defined(HBM)
		return MemoryInterface::getInstance().search_entry<TS, MS, AS, TABLE_TYPE>(memPtr, index, key, value);
#else
		return MemoryInterface::getInstance().search_entry<TS, MS, AS, TABLE_TYPE>(lookup, index, key, value);
#endif
	}

#if !(defined(DDR) or defined(HBM))
	volatile LookupEntry<MS, AS> lookup[TS];
#endif
};

#endif // MATCH_ACTION_TABLE_H
