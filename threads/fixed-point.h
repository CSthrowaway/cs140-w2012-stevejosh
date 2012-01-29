#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

typedef int real;

real fixed_point_create (int num, int denom);
real fixed_point_multiply (real x, real y);
real fixed_point_divide (real x, real y);
int  fixed_point_round_down (real x);
int  fixed_point_round_nearest (real x);

#endif
