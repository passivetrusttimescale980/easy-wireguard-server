#include "mini_qr.hpp"
#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>

namespace miniqr {
namespace {

static const int kRsLen[40] = {3,3,3,3,3,3,3,3,3,6,3,6,3,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,3,6,6,6,6,6,6,6,6};
static const int kRsL[40][6] = {
    {1,26,19,0,0,0},
    {1,44,34,0,0,0},
    {1,70,55,0,0,0},
    {1,100,80,0,0,0},
    {1,134,108,0,0,0},
    {2,86,68,0,0,0},
    {2,98,78,0,0,0},
    {2,121,97,0,0,0},
    {2,146,116,0,0,0},
    {2,86,68,2,87,69},
    {4,101,81,0,0,0},
    {2,116,92,2,117,93},
    {4,133,107,0,0,0},
    {3,145,115,1,146,116},
    {5,109,87,1,110,88},
    {5,122,98,1,123,99},
    {1,135,107,5,136,108},
    {5,150,120,1,151,121},
    {3,141,113,4,142,114},
    {3,135,107,5,136,108},
    {4,144,116,4,145,117},
    {2,139,111,7,140,112},
    {4,151,121,5,152,122},
    {6,147,117,4,148,118},
    {8,132,106,4,133,107},
    {10,142,114,2,143,115},
    {8,152,122,4,153,123},
    {3,147,117,10,148,118},
    {7,146,116,7,147,117},
    {5,145,115,10,146,116},
    {13,145,115,3,146,116},
    {17,145,115,0,0,0},
    {17,145,115,1,146,116},
    {13,145,115,6,146,116},
    {12,151,121,7,152,122},
    {6,151,121,14,152,122},
    {17,152,122,4,153,123},
    {4,152,122,18,153,123},
    {20,147,117,4,148,118},
    {19,148,118,6,149,119}
};
static const int kPosLen[40] = {0,2,2,2,2,2,3,3,3,3,3,3,3,4,4,4,4,4,4,4,5,5,5,5,5,5,5,6,6,6,6,6,6,6,7,7,7,7,7,7};
static const int kPos[40][7] = {
    {0,0,0,0,0,0,0},
    {6,18,0,0,0,0,0},
    {6,22,0,0,0,0,0},
    {6,26,0,0,0,0,0},
    {6,30,0,0,0,0,0},
    {6,34,0,0,0,0,0},
    {6,22,38,0,0,0,0},
    {6,24,42,0,0,0,0},
    {6,26,46,0,0,0,0},
    {6,28,50,0,0,0,0},
    {6,30,54,0,0,0,0},
    {6,32,58,0,0,0,0},
    {6,34,62,0,0,0,0},
    {6,26,46,66,0,0,0},
    {6,26,48,70,0,0,0},
    {6,26,50,74,0,0,0},
    {6,30,54,78,0,0,0},
    {6,30,56,82,0,0,0},
    {6,30,58,86,0,0,0},
    {6,34,62,90,0,0,0},
    {6,28,50,72,94,0,0},
    {6,26,50,74,98,0,0},
    {6,30,54,78,102,0,0},
    {6,28,54,80,106,0,0},
    {6,32,58,84,110,0,0},
    {6,30,58,86,114,0,0},
    {6,34,62,90,118,0,0},
    {6,26,50,74,98,122,0},
    {6,30,54,78,102,126,0},
    {6,26,52,78,104,130,0},
    {6,30,56,82,108,134,0},
    {6,34,60,86,112,138,0},
    {6,30,58,86,114,142,0},
    {6,34,62,90,118,146,0},
    {6,30,54,78,102,126,150},
    {6,24,50,76,102,128,154},
    {6,28,54,80,106,132,158},
    {6,32,58,84,110,136,162},
    {6,26,54,82,110,138,166},
    {6,30,58,86,114,142,170}
};

struct RsBlock { int total = 0; int data = 0; };

static std::array<int,256> gExp{};
static std::array<int,256> gLog{};
static bool gGfReady = false;

void InitGf() {
    if (gGfReady) return;
    for (int i=0;i<8;++i) gExp[i]=1<<i;
    for (int i=8;i<256;++i) gExp[i]=gExp[i-4]^gExp[i-5]^gExp[i-6]^gExp[i-8];
    for (int i=0;i<255;++i) gLog[gExp[i]]=i;
    gGfReady=true;
}
int GExp(int n) { InitGf(); while(n<0)n+=255; return gExp[n%255]; }

std::vector<RsBlock> BlocksFor(int version) {
    std::vector<RsBlock> out;
    const int* r=kRsL[version-1];
    for(int i=0;i<kRsLen[version-1];i+=3) {
        for(int n=0;n<r[i];++n) out.push_back({r[i+1],r[i+2]});
    }
    return out;
}

struct Bits {
    std::vector<std::uint8_t> b;
    int len=0;
    void bit(bool v) {
        int i=len/8; if(i>=static_cast<int>(b.size())) b.push_back(0);
        if(v) b[i]|=static_cast<std::uint8_t>(0x80u>>(len%8));
        ++len;
    }
    void put(unsigned v,int n) { for(int i=n-1;i>=0;--i) bit(((v>>i)&1u)!=0); }
};

std::vector<std::uint8_t> RsGenerator(int degree) {
    std::vector<std::uint8_t> gen(1,1);
    for(int i=0;i<degree;++i) {
        std::vector<std::uint8_t> next(gen.size()+1,0);
        int a=GExp(i);
        for(size_t j=0;j<gen.size();++j) {
            next[j]^=gen[j];
            if(gen[j]) next[j+1]^=static_cast<std::uint8_t>(GExp(gLog[gen[j]]+gLog[a]));
        }
        gen.swap(next);
    }
    return gen;
}

std::vector<std::uint8_t> MakeCodewords(int version,const std::string& text,std::string& err) {
    auto blocks=BlocksFor(version);
    int totalData=0; for(auto&b:blocks) totalData+=b.data;
    int limit=totalData*8;
    Bits bits;
    bits.put(0x4,4); // byte mode
    int countBits=version<10?8:16;
    if(text.size() >= (countBits==8?256u:65536u)) { err="QR payload too long"; return {}; }
    bits.put(static_cast<unsigned>(text.size()),countBits);
    for(unsigned char c:text) bits.put(c,8);
    if(bits.len>limit) { err="QR payload does not fit"; return {}; }
    for(int i=0;i<std::min(4,limit-bits.len);++i) bits.bit(false);
    while(bits.len%8) bits.bit(false);
    bool toggle=false;
    while(bits.len<limit) { bits.put(toggle?0x11:0xEC,8); toggle=!toggle; }

    std::vector<std::vector<std::uint8_t>> dc,ec;
    int off=0,maxDc=0,maxEc=0;
    for(auto& bl:blocks) {
        int ecCount=bl.total-bl.data; maxDc=std::max(maxDc,bl.data); maxEc=std::max(maxEc,ecCount);
        std::vector<std::uint8_t> d(bits.b.begin()+off,bits.b.begin()+off+bl.data); off+=bl.data;
        auto gen=RsGenerator(ecCount);
        std::vector<std::uint8_t> msg=d; msg.resize(d.size()+ecCount,0);
        for(int i=0;i<bl.data;++i) {
            int coef=msg[i]; if(!coef) continue;
            int lg=gLog[coef];
            for(size_t j=0;j<gen.size();++j) if(gen[j]) msg[i+j]^=static_cast<std::uint8_t>(GExp(lg+gLog[gen[j]]));
        }
        std::vector<std::uint8_t> e(msg.end()-ecCount,msg.end());
        dc.push_back(std::move(d)); ec.push_back(std::move(e));
    }
    std::vector<std::uint8_t> out;
    for(int i=0;i<maxDc;++i) for(auto&d:dc) if(i<static_cast<int>(d.size())) out.push_back(d[i]);
    for(int i=0;i<maxEc;++i) for(auto&e:ec) if(i<static_cast<int>(e.size())) out.push_back(e[i]);
    return out;
}

int BchDigit(int d) { int n=0; while(d){++n;d>>=1;} return n; }
int BchTypeInfo(int data) {
    constexpr int G15=(1<<10)|(1<<8)|(1<<5)|(1<<4)|(1<<2)|(1<<1)|1;
    constexpr int MASK=(1<<14)|(1<<12)|(1<<10)|(1<<4)|(1<<1);
    int d=data<<10; while(BchDigit(d)-BchDigit(G15)>=0) d^=G15<<(BchDigit(d)-BchDigit(G15));
    return ((data<<10)|d)^MASK;
}
int BchTypeNumber(int data) {
    constexpr int G18=(1<<12)|(1<<11)|(1<<10)|(1<<9)|(1<<8)|(1<<5)|(1<<2)|1;
    int d=data<<12; while(BchDigit(d)-BchDigit(G18)>=0) d^=G18<<(BchDigit(d)-BchDigit(G18));
    return (data<<12)|d;
}

struct Matrix {
    int n; std::vector<int8_t> m;
    explicit Matrix(int s):n(s),m(static_cast<size_t>(s)*s,-1){}
    int8_t& at(int r,int c){return m[static_cast<size_t>(r)*n+c];}
    void probe(int row,int col){
        for(int r=-1;r<=7;++r){ if(row+r<0||row+r>=n)continue; for(int c=-1;c<=7;++c){ if(col+c<0||col+c>=n)continue;
            bool dark=(r>=0&&r<=6&&(c==0||c==6))||(c>=0&&c<=6&&(r==0||r==6))||(r>=2&&r<=4&&c>=2&&c<=4);
            at(row+r,col+c)=dark?1:0;
        }}
    }
    void align(int version){
        int ln=kPosLen[version-1]; const int* pos=kPos[version-1];
        for(int i=0;i<ln;++i)for(int j=0;j<ln;++j){int row=pos[i],col=pos[j];if(at(row,col)!=-1)continue;
            for(int r=-2;r<=2;++r)for(int c=-2;c<=2;++c) at(row+r,col+c)=(r==-2||r==2||c==-2||c==2||(r==0&&c==0))?1:0;
        }
    }
    void timing(){for(int r=8;r<n-8;++r)if(at(r,6)==-1)at(r,6)=r%2==0;for(int c=8;c<n-8;++c)if(at(6,c)==-1)at(6,c)=c%2==0;}
    void typeNumber(int version){if(version<7)return;int bits=BchTypeNumber(version);for(int i=0;i<18;++i){int v=(bits>>i)&1;at(i/3,i%3+n-11)=v;at(i%3+n-11,i/3)=v;}}
    void typeInfo(int mask){int data=(1<<3)|mask;int bits=BchTypeInfo(data);for(int i=0;i<15;++i){int v=(bits>>i)&1;if(i<6)at(i,8)=v;else if(i<8)at(i+1,8)=v;else at(n-15+i,8)=v;}
        for(int i=0;i<15;++i){int v=(bits>>i)&1;if(i<8)at(8,n-i-1)=v;else if(i<9)at(8,15-i)=v;else at(8,15-i-1)=v;}at(n-8,8)=1;}
    static bool mask0(int r,int c){return (r+c)%2==0;}
    void map(const std::vector<std::uint8_t>& data){int inc=-1,row=n-1,bit=7,byte=0;for(int col=n-1;col>0;col-=2){if(col<=6)--col;for(;;){for(int c:{col,col-1})if(at(row,c)==-1){bool dark=false;if(byte<static_cast<int>(data.size()))dark=((data[byte]>>bit)&1)!=0;if(mask0(row,c))dark=!dark;at(row,c)=dark?1:0;if(--bit<0){++byte;bit=7;}}row+=inc;if(row<0||row>=n){row-=inc;inc=-inc;break;}}}}
};

} // namespace

bool EncodeUtf8(const std::string& text,QrCode& out,std::string& error) {
    error.clear(); out={};
    int version=0;
    for(int v=1;v<=40;++v){auto blocks=BlocksFor(v);int cap=0;for(auto&b:blocks)cap+=b.data*8;int needed=4+(v<10?8:16)+static_cast<int>(text.size())*8;if(needed<=cap){version=v;break;}}
    if(!version){error="QR payload too long";return false;}
    auto data=MakeCodewords(version,text,error);if(data.empty()&&!text.empty())return false;
    Matrix q(version*4+17);q.probe(0,0);q.probe(q.n-7,0);q.probe(0,q.n-7);q.align(version);q.timing();q.typeInfo(0);q.typeNumber(version);q.map(data);
    out.size=q.n;out.modules.resize(static_cast<size_t>(q.n)*q.n);for(size_t i=0;i<q.m.size();++i)out.modules[i]=q.m[i]>0?1:0;return true;
}

} // namespace miniqr
