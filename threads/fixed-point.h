/* 17.14 Fixed-Point Arithmetic Operations */
#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define Q 14
#define F (1 << Q)

typedef int real;

/* Return the real number obtained by dividing integer num by
   integer denom. */
real
fixed_point_create (int num, int denom)
{
  return (num * F) / denom;
}

/* Return the real number obtained by multiplying two real numbers
   x and y together. */
real
fixed_point_multiply (real x, real y)
{
  return ((int64_t)x) * y / F;
}

/* Return the real number obtained by dividing real number x by
   real number y. */
real
fixed_point_divide (real x, real y)
{
  return ((int64_t)x) * F / y;
}

/* Return the integer obtained by rounding real number x down */
int
fixed_point_round_down (real x)
{
  return x / F;
}

/* Return the integer obtained by rounding real number x to the
   nearest integer. */
int
fixed_point_round_nearest (real x)
{
  return (x >= 0) ? (x + F/2) / F : (x - F/2) / F;
}

#endif
