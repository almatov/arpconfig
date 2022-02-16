/* arpconfig.cc
****************************************************************************************************************
****************************************************************************************************************

    Copyright (C) 2022 Askar Almatov

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
    Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
    implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see
    <https://www.gnu.org/licenses/>.
*/

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <getopt.h>
#include <libnet.h>
#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>

using std::cerr;
using std::cout;
using std::endl;
using std::hex;
using std::map;
using std::setfill;
using std::setw;
using std::string;
using std::ostringstream;

constexpr const char*   VERSION_        = "0.2";
constexpr const char*   FILTER_STRING_  = "inbound and (arp or ip)";
constexpr const char*   IP_UTILITY_     = "ip";
constexpr const int     CAP_LENGTH_     = 80;

struct ConfigData
{
    uint16_t            id              = 13485;
    uint8_t             myMac[ 6 ]      = { 0 };
    uint8_t             gwMac[ 6 ]      = { 0 };
    uint8_t             randomMac[ 6 ]  = { 0x0, 0xe0, 0x4c };  // Realtek OUI
    uint32_t            myIp            = 0;
    uint32_t            gwIp            = 0;
    int                 prefix          = 31;
    bool                isArpRequest    = false;
    bool                shouldConfigure = false;
    bool                shouldTest      = false;
    map<int, uint32_t>  gateways;

                        ConfigData();
    void                arpReply( const char* interfaceName );
    void                bootpProvocate( const char* interfaceName );
    void                gatewayTest( const char* interfaceName );
};

/**************************************************************************************************************/
ConfigData::ConfigData()
{
    struct timespec     ts;

    clock_gettime( CLOCK_MONOTONIC_RAW, &ts );
    memcpy( randomMac + 3, &ts.tv_nsec, 3 );
}

/**************************************************************************************************************/
void
ConfigData::arpReply( const char* interfaceName )
{
    static char     lnetErr[ LIBNET_ERRBUF_SIZE ];
    libnet_t*       lnet = libnet_init( LIBNET_LINK, interfaceName, lnetErr );

    if ( lnet != nullptr )
    {
        uint32_t        beSip = htonl( myIp );
        uint32_t        beDip = htonl( gwIp );
        const uint8_t*  sip = reinterpret_cast<const uint8_t*>( &beSip );
        const uint8_t*  dip = reinterpret_cast<const uint8_t*>( &beDip );

        libnet_autobuild_arp( ARPOP_REPLY, myMac, sip, gwMac, dip, lnet );
        libnet_build_ethernet( gwMac, myMac, ETHERTYPE_ARP, nullptr, 0, lnet, 0 );
        libnet_write( lnet );
        libnet_destroy( lnet );
    }
}

/**************************************************************************************************************/
void
ConfigData::bootpProvocate( const char* interfaceName )
{
    static char     lnetErr[ LIBNET_ERRBUF_SIZE ];
    libnet_t*       lnet = libnet_init( LIBNET_LINK, interfaceName, lnetErr );

    if ( lnet != nullptr )
    {
        static uint8_t  payload[ 60 ] = { 53, 1, 1, 255, 0 };               // RFC2132 DHCPDISCOVER
        uint32_t        sip = 0;                                            // 0.0.0.0
        uint32_t        dip = 0xffffffff;                                   // 255.255.255.255
        uint8_t         dmac[ 6 ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // broadcast MAC

        libnet_build_bootpv4( 1, 1, 6, 0, 9, 0, 0, 0, 0, 0, 0, randomMac, nullptr, nullptr, payload, sizeof(payload), lnet, 0 ); 
        libnet_build_udp( 68, 67, 308, 0, nullptr, 0, lnet, 0 );
        libnet_build_ipv4( 328, 0, 0, 0, 8, 17, 0, htonl(sip), htonl(dip), nullptr, 0, lnet, 0 );
        libnet_build_ethernet( dmac, randomMac, ETHERTYPE_IP, nullptr, 0, lnet, 0 );
        libnet_write( lnet );
        libnet_destroy( lnet );
    }
}

/**************************************************************************************************************/
void
ConfigData::gatewayTest( const char* interfaceName )
{
    static char     lnetErr[ LIBNET_ERRBUF_SIZE ];
    libnet_t*       lnet = libnet_init( LIBNET_LINK, interfaceName, lnetErr );

    if ( lnet != nullptr )
    {
        static uint8_t  payload[ 32 ] = { 0 };
        uint32_t        dip = 0x08080808;                                   // 8.8.8.8

        libnet_build_udp( 33427, 33434, 40, 0, payload, sizeof(payload), lnet, 0 );
        libnet_build_ipv4( 60, 0, id, 0, 1, 17, 0, htonl(myIp), htonl(dip), nullptr, 0, lnet, 0 );
        libnet_build_ethernet( gwMac, myMac, ETHERTYPE_IP, nullptr, 0, lnet, 0 );
        libnet_write( lnet );
        libnet_destroy( lnet );
    }
}

/**************************************************************************************************************/
static string
linkCommand_( const char* interfaceName, const char* state )
{
    return move( string(IP_UTILITY_) + " link set " + interfaceName + " " + state );
}

/**************************************************************************************************************/
static string
macCommand_( const char* interfaceName, const uint8_t* mac )
{
    ostringstream   oss;

    oss << IP_UTILITY_ << " link set " << interfaceName << " address " << hex <<
        setw( 2 ) << setfill( '0' ) << static_cast<unsigned>( mac[0] ) << ":" <<
        setw( 2 ) << setfill( '0' ) << static_cast<unsigned>( mac[1] ) << ":" <<
        setw( 2 ) << setfill( '0' ) << static_cast<unsigned>( mac[2] ) << ":" <<
        setw( 2 ) << setfill( '0' ) << static_cast<unsigned>( mac[3] ) << ":" <<
        setw( 2 ) << setfill( '0' ) << static_cast<unsigned>( mac[4] ) << ":" <<
        setw( 2 ) << setfill( '0' ) << static_cast<unsigned>( mac[5] );

    return move( oss.str() );
}

/**************************************************************************************************************/
static string
ipClearCommand_( const char* interfaceName )
{
    return move( string(IP_UTILITY_) + " address flush dev " + interfaceName );
}

/**************************************************************************************************************/
static string
ipAddCommand_( const char* interfaceName, uint32_t ip, int prefix )
{
    ostringstream   oss;

    oss <<
        IP_UTILITY_ << " address add " <<
        ( ip >> 24 ) << "." << ( (ip >> 16) & 0xff ) << "." << ( (ip >> 8) & 0xff ) << "." << ( ip & 0xff ) <<
        "/" << prefix << " dev " << interfaceName;

    return move( oss.str() );
}

/**************************************************************************************************************/
static string
routeCommand_( const char* netString, uint32_t gw )
{
    ostringstream   oss;

    oss <<
        IP_UTILITY_ << " route replace " << netString << " via " << 
        ( gw >> 24 ) << "." << ( (gw >> 16) & 0xff ) << "." << ( (gw >> 8) & 0xff ) << "." << ( gw & 0xff );

    return move( oss.str() );
}

/**************************************************************************************************************/
static void
packetProcessing_
(
    uint8_t*                    userData,
    const struct pcap_pkthdr*   pcapHeader,
    const uint8_t*              packet
)
{
    ConfigData*     conf = reinterpret_cast<ConfigData*>( userData );
    const uint8_t*  dmac = packet;

    ++conf->id;
    memcpy( conf->gwMac, packet + 6, sizeof(conf->gwMac) );
    memcpy( conf->myMac, ((dmac[0]&1)? conf->randomMac : dmac), sizeof(conf->myMac) );
    conf->isArpRequest = false;
    conf->shouldConfigure = false;
    conf->shouldTest = false;

    if ( memcmp(packet+12, "\x8\x6\0\x1", 4) == 0 )
    {
        // ARP request
        conf->gwIp = ntohl( *reinterpret_cast<const uint32_t*>(packet + 28) );
        conf->myIp = ntohl( *reinterpret_cast<const uint32_t*>(packet + 38) );

        if ( conf->gwIp != conf->myIp )
        {
            conf->gateways[ conf->id ] = conf->gwIp;
            conf->isArpRequest = true;
            conf->shouldTest = true;
        }

        return;
    }
    
    if ( memcmp(packet+34, "\0\x43\0\x44", 4) == 0 && memcmp(packet+46, "\0\0\0\x9", 4) == 0 )
    {
        // BOOTP reply
        conf->myIp = ntohl( *reinterpret_cast<const uint32_t*>(packet + 58) );
        conf->shouldTest = true;
        return;
    }

    // any packet
    conf->myIp = ntohl( *reinterpret_cast<const uint32_t*>(packet + 30) );
    conf->shouldTest = !( dmac[0] & 1 );

    if
    (
        packet[ 23 ] == 1 &&                                                        // ICMP
        ( packet[34] == 11 || packet[34] == 3 ) &&                                  // type
        ntohl( *reinterpret_cast<const uint32_t*>(packet + 54) ) == conf->myIp &&   // sender IP
        ntohl( *reinterpret_cast<const uint32_t*>(packet + 58) ) == 0x08080808 &&   // destination IP
        ntohs( *reinterpret_cast<const uint16_t*>(packet + 62) ) == 33427 &&        // sender port
        ntohs( *reinterpret_cast<const uint16_t*>(packet + 64) ) == 33434           // destination port
    )
    {
        // gateway response
        conf->gwIp = conf->gateways[ ntohs(*reinterpret_cast<const uint16_t*>(packet+46)) ];

        if ( conf->gwIp == 0 )
        {
            conf->gwIp = ntohl( *reinterpret_cast<const uint32_t*>(packet + 26) );
        }

        conf->prefix = 31;

        for ( unsigned diff = conf->gwIp ^ conf->myIp; diff >>= 1; conf->prefix-- ) {}

        if ( conf->prefix >= 20 )
        {
            conf->shouldConfigure = true;
            conf->shouldTest = false;
        }
    }
}

/**************************************************************************************************************/
int
main( int argc, char* argv[] )
{
    const char*     progName = program_invocation_short_name;
    bool            execMode = false;
    int             opt;

    static const struct option  longOptions[] =
    {
        { "exec",    no_argument, nullptr, 'e' },
        { "version", no_argument, nullptr, 'v' },
        { "help",    no_argument, nullptr, 'h' },
        { nullptr,   0,           nullptr,  0  }
    };

    while ( (opt = getopt_long(argc,argv,"evh",longOptions,nullptr)) != -1 )
    {
        switch ( opt )
        {
            case 'e':
                execMode = true;
                break;

            case 'v':
                cout << progName << " version " << VERSION_ << endl;
                return EXIT_SUCCESS;

            case 'h':
            default:
                cout <<
                    progName << " predict ARP values or provocate ARP requests then configure interface\n"
                    "Usage: " << progName << " [options] interface\n"
                    "\t-e --exec\tExecute configuration commands\n"
                    "\t-v --version\tPrint version information\n"
                    "\t-h --help\tPrint help message\n";
                return EXIT_SUCCESS;
        }
    }

    argc -= optind;
    argv += optind;

    if ( argc < 1 )
    {
        cerr << progName << ": interface must be specified" << endl;
        return EXIT_FAILURE;
    }

    const char*         interfaceName = argv[ 0 ];
    static char         pcapErr[ PCAP_ERRBUF_SIZE ];
    struct bpf_program  filter;
    pcap_t*             pcap = pcap_open_live( interfaceName, CAP_LENGTH_, true, 1000, pcapErr );

    if ( pcap == nullptr )
    {
        cerr << pcapErr << endl;
        return EXIT_FAILURE;
    }

    if
    (
        pcap_compile( pcap, &filter, FILTER_STRING_, true, 0 ) ||
        pcap_setfilter( pcap, &filter ) ||
        pcap_setnonblock( pcap, 1, pcapErr )
    )
    {
        cerr << pcap_geterr( pcap ) << endl;
        pcap_close( pcap );
        return EXIT_FAILURE;
    }

    ConfigData  conf;

    while ( !conf.shouldConfigure )
    {
        static int  cycle = 0;

        if ( ++cycle % 400 == 0 )   // about 40 seconds
        {
            conf.bootpProvocate( interfaceName );
        }

        if ( pcap_dispatch(pcap, 1, packetProcessing_, reinterpret_cast<uint8_t*>(&conf)) <= 0 )
        {
            usleep( 100000 );       // 0.1 seconds
            continue;
        }

        if ( conf.isArpRequest )
        {
            conf.arpReply( interfaceName );
            usleep( 100000 );       // 0.1 seconds
        }

        if ( conf.shouldTest )
        {
            conf.gatewayTest( interfaceName );
        }
    }

    string  cmdDown( linkCommand_(interfaceName, "down") );
    string  cmdUp( linkCommand_(interfaceName, "up") );
    string  cmdMac( macCommand_(interfaceName, conf.myMac) );
    string  cmdIpClear( ipClearCommand_(interfaceName) );
    string  cmdIpAdd( ipAddCommand_(interfaceName, conf.myIp, conf.prefix) );
    string  cmdRoute0( routeCommand_("0.0.0.0/1", conf.gwIp) );
    string  cmdRoute128( routeCommand_("128.0.0.0/1", conf.gwIp) );

    if ( execMode )
    {
        system( cmdDown.c_str() );
        system( cmdMac.c_str() );
        system( cmdUp.c_str() );
        system( cmdIpClear.c_str() );
        system( cmdIpAdd.c_str() );
        system( cmdRoute0.c_str() );
        system( cmdRoute128.c_str() );
    }
    else
    {
        cout << cmdDown << endl;
        cout << cmdMac << endl;
        cout << cmdUp << endl;
        cout << cmdIpClear << endl;
        cout << cmdIpAdd << endl;
        cout << cmdRoute0 << endl;
        cout << cmdRoute128 << endl;
    }

    pcap_close( pcap );
    return EXIT_SUCCESS;
}
