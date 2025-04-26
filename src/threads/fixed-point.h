#ifndef FixedPoint_H
#define FixedPoint_H
#include<stdint.h>



#define FIXED_POINT_Q 14
#define FIXED_POINT_F (1 << FIXED_POINT_Q)


typedef int fixed_point;

/* Convert n to fixed point: */
#define INT_TO_FP(n) (n * FIXED_POINT_F)

/* Convert x to integer (rounding toward zero): */
#define FP_TO_INT_ZERO(x) ((x) / FIXED_POINT_F)

/* Convert x to integer (rounding to nearest): */
#define FP_TO_INT_NEAREST(x) (((x)>=0) ? (((x)+FIXED_POINT_F/2)/FIXED_POINT_F):((x)-FIXED_POINT_F/2)/FIXED_POINT_F)

/* Add two fixed-point numbers: */
#define ADD_FP(x, y)((x)+(y))

/* Subtract y from x: */
#define SUB_FP(x, y)((x)-(y))

/* Add fixed-point and int: */
#define ADD_MIX(x, n)((x)+(n)*FIXED_POINT_F)

/* Subtract int from fixed-point: */
#define SUB_MIX(x, n)((x)-(n)*f)

/* Multiply two fixed-point numbers: */
#define MUL_FP(x, y)(((int64_t) x) *(y)/ FIXED_POINT_F)

/* Multiply fixed-point by int: */
#define MUL_MIX(x, n)((x)*(n))

/* Divide x by y (both fixed-point): */
#define DIV_FP(x, y) ((int32_t)(((int64_t)(x))*FIXED_POINT_F /(y)))

/* Divide fixed-point by int: */
#define DIV_MIX(x, n)((x) / (n))

#endif 
