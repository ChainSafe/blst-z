import {binding} from "./binding.js";

export const SECRET_KEY_SIZE = 32;
export const PUBLIC_KEY_SIZE = 96;
export const PUBLIC_KEY_COMPRESS_SIZE = 48;

export const SIGNATURE_LENGTH = 192;
export const SIGNATURE_LENGTH_COMPRESSED = 96;

export const MESSAGE_LENGTH = 32;
export const MAX_SIGNATURE_SETS_PER_JOB = 128;
export const MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB = 128;
export const MAX_AGGREGATE_PER_JOB = 128;
export const BLST_SUCCESS = 0;
export const BLST_BAD_ENCODING = 1;
export const BLST_POINT_NOT_ON_CURVE = 2;
export const BLST_POINT_NOT_IN_GROUP = 3;
export const BLST_AGGR_TYPE_MISMATCH = 4;
export const BLST_VERIFY_FAIL = 5;
export const BLST_PK_IS_INFINITY = 6;
export const BLST_BAD_SCALAR = 7;
