tsec,hashbytes = 125,16
#tsec,hashbytes = 192,24
#tsec,hashbytes = 253,32
maxsigs=2**64
F = RealField(100)

def ld(r):
    return -F(log(1/F(2**(8*hashbytes))+F(r)) / log2)

def pow(p,e):
    return F(p)**e

def qhitprob(qs,r):
    p = F(1/leaves)
    return binomial(qs,r)*(pow(p,r))*(pow(1-p,qs-r))

def la(m,w):
    return ceil(m / log(w,2))

def lb(m,w):
    return floor( log(la(m,w)*(w-1), 2) / log(w,2)) + 1

def lc(m,w):
    return la(m,w) + lb(m,w)

for h in range(35,74,2):
    leaves = 2**h
    for b in range(4,17):
        for k in range(30,32):
            sigma=0
            r = 1
            while True:
                r = F(r)
                p = min(1,F((r/F(2**b)))**k)
                q = qhitprob(maxsigs,int(r))*p
                sigma += q
                r += 1
                if(r > maxsigs/leaves and q < F(2)**(-10*tsec)): # beyond expected number of collisions and
                    break
            if(sigma<2**-tsec):
                for d in range(4,h):
                    if(h % d == 0 and h <= 64+(h/d)):
                        for w in [16,256]:
                            wots = lc(8*hashbytes,w)
                            sigsize = ((b+1)*k+h+wots*d+1)*hashbytes
                            if(sigsize < 50000):
                                print(h, end=' ')  # total tree height
                                print(d, end=' ')  # number of tree layers, subtree height is h/d
                                print(b, end=' ')  # height of FORS trees
                                print(k, end=' ')  # number of trees for FORS
                                print(w, end=' ')  # Winternitz parameter
                                print(round(ld(sigma)), end=' ')
                                print(sigsize, end=' ')
                                # Speed estimate based on (rough) hash count
                                print(k*2**(b+1) + d*(2**(h/d)*(wots*w+1)))
