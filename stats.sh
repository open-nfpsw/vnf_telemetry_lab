NFP=`ethtool -i p1p1 | grep bus-info | awk -F\. '{print $2}'`

if ! nfp-rtsym -n $NFP -L 2> /dev/null | grep _tsopt_data > /dev/null ; then
  exit 1
fi

SPEED=`nfp-hwinfo -n $NFP me.speed | awk -F= '{print $2}'`

MAX=`nfp-rtsym -n $NFP -vl 8 _tsopt_data:0x6020`
MAX=`echo $SPEED $MAX | awk -n '{val = $3 * 2^32 + $4; print (val * 16 / $1 / 1000)}'`

MIN=`nfp-rtsym -n $NFP -vl 8 _tsopt_data:0x6028`
MIN=`echo $SPEED $MIN | awk -n '{val = $3 * 2^32 + $4; print (val * 16 / $1 / 1000)}'`

TOTAL=`nfp-rtsym -n $NFP -vl 8 _tsopt_data:0x6038`
TOTAL=`echo $SPEED $TOTAL | awk -n '{val = $3 * 2^32 + $4; print (val * 16 / $1 / 1000)}'`


PACKETS=`nfp-rtsym -n $NFP -vl 8 _tsopt_data:0x6030 | awk -n '{val = $2 * 2^32 + $3; print val}'`



echo NFP: $NFP 
echo SPEED: $SPEED MHz
echo PACKETS: $PACKETS
echo MAX: $MAX ms
echo MIN: $MIN ms
if [ $PACKETS -gt 0 ]; then
  echo AVE: `echo "$TOTAL $PACKETS" | awk '{print ($1 / $2)}'` ms
fi

