// © 2020 Erik Rigtorp <erik@rigtorp.se>
// SPDX-License-Identifier: MIT

#include <cstring>
#include <iostream>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <limits>

#define NANOSECONDS_PER_SECOND 1000000000L

static void fatal_error(const char* what) {
  std::cerr << what << "\n";
  exit(1);
}

// Note: returns a pointer to a static buffer.
static const char* timestr(const struct timespec &ts) {
  struct tm t;
  if (localtime_r(&(ts.tv_sec), &t) == NULL) {
    fatal_error("localtime_r failed");
  }

  static char buf[50];
  size_t len = sizeof(buf);
  const int bytes_written = strftime(buf, len, "%F %T", &t);
  if (bytes_written <= 0) {
    fatal_error("strftime failed (buffer too small)");
  }
  len -= size_t(bytes_written);

  snprintf(&buf[bytes_written], len, ".%09ld", ts.tv_nsec);

  return buf;
}

// Assumes nanosecond timestamps (PCAP_TSTAMP_PRECISION_NANO)
inline const char* timestr(const pcap_pkthdr &h) {
  const struct timespec ts = { h.ts.tv_sec, h.ts.tv_usec };
  return timestr(ts);
}

inline double to_seconds(const struct timespec& t) {
  return double(t.tv_sec) + (1e-9 * t.tv_nsec);
}

struct packet_stats {
  long long sent;       // packets sent
  long long truncated;  // packets skipped b/c header.len != header.caplen
  long long skipped;    // packets skipped for other reasons (non-IP4, non-UDP)

  packet_stats() { reset(); }
  void reset() { memset(this, 0, sizeof(*this)); }
};

int main(int argc, char *argv[]) {
  tzset();

  int ifindex = 0;
  int loopback = 0;
  double speed = 1;
  long long interval = -1;
  int repeat = 1;
  int ttl = -1;
  int broadcast = 0;
  long long max_packets = std::numeric_limits<long long>::max();
  double display_interval = -1;

  int opt;
  while ((opt = getopt(argc, argv, "i:bls:c:r:t:d:p:")) != -1) {
    switch (opt) {
    case 'i':
      ifindex = if_nametoindex(optarg);
      if (ifindex == 0) {
        std::cerr << "if_nametoindex: " << strerror(errno) << std::endl;
        return 1;
      }
      break;
    case 'l':
      loopback = 1;
      break;
    case 's':
      speed = std::stod(optarg);
      if (speed < 0) {
        std::cerr << "speed must be positive" << std::endl;
      }
      break;
    case 'c':
      interval = std::stoll(optarg);
      if (interval < 0) {
        std::cerr << "interval must be non-negative integer" << std::endl;
        return 1;
      }
      break;
    case 'r':
      repeat = std::stoi(optarg);
      if (repeat != -1 && repeat <= 0) {
        std::cerr << "repeat must be positive integer or -1" << std::endl;
        return 1;
      }
      break;
    case 't':
      ttl = std::stoi(optarg);
      if (ttl < 0) {
        std::cerr << "ttl must be non-negative integer" << std::endl;
        return 1;
      }
      break;
    case 'b':
      broadcast = 1;
      break;
    case 'd':
      display_interval = std::stod(optarg);
      break;
    case 'p':
      max_packets = std::stoll(optarg);
      if (max_packets < 0) {
        std::cerr << "max_packets must be non-negative\n";
        return 1;
      }
      break;
    default:
      goto usage;
    }
  }
  if (optind >= argc) {
  usage:
    std::cerr
        << "udpreplay 1.0.0 © 2020 Erik Rigtorp <erik@rigtorp.se> "
           "https://github.com/rigtorp/udpreplay\n"
           "usage: udpreplay [-i iface] [-l] [-s speed] [-c millisec] [-r "
           "repeat] [-t ttl] "
           "pcap\n"
           "\n"
           "  -i iface    interface to send packets through\n"
           "  -l          enable loopback\n"
           "  -c microsec constant microseconds between packets\n"
           "  -r repeat   number of times to loop data (-1 for infinite loop)\n"
           "  -s speed    replay speed relative to pcap timestamps\n"
           "  -t ttl      packet ttl\n"
           "  -b          enable broadcast (SO_BROADCAST)\n"
           "  -d seconds  progress display interval (seconds)\n"
           "  -p packets  max number of packets to send\n"
        << std::endl;
    return 1;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    std::cerr << "socket: " << strerror(errno) << std::endl;
    return 1;
  }

  if (ifindex != 0) {
    ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_ifindex = ifindex;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) ==
        -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (loopback != 0) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback,
                   sizeof(loopback)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (broadcast != 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast,
                   sizeof(broadcast)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (ttl != -1) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  timespec deadline = {};
  if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
    std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
    return 1;
  }

  packet_stats stats;
  long long packet_count = 0;

  for (int i = 0; (repeat == -1 || i < repeat)
                  && packet_count < max_packets; i++) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline_with_tstamp_precision(
        argv[optind], PCAP_TSTAMP_PRECISION_NANO, errbuf);

    if (handle == nullptr) {
      std::cerr << "pcap_open: " << errbuf << std::endl;
      return 1;
    }

    timespec start = {-1, -1};
    timespec pcap_start = {-1, -1};
    timespec display_time = {-1, -1};

    pcap_pkthdr header;
    const u_char *p;
    while ((p = pcap_next(handle, &header))) {
      if (start.tv_nsec == -1) {
        if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
          std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
          return 1;
        }
        display_time = start;
        pcap_start.tv_sec = header.ts.tv_sec;
        pcap_start.tv_nsec =
            header.ts.tv_usec; // Note PCAP_TSTAMP_PRECISION_NANO
      }
      // Note header.len may be less than header.caplen in some recordings
      if (header.len > header.caplen) {
        ++stats.truncated;
        continue;
      }
      auto eth = reinterpret_cast<const ether_header *>(p);

      // jump over and ignore vlan tags
      while (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
        p += 4;
        eth = reinterpret_cast<const ether_header *>(p);
      }
      if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        ++stats.skipped;
        continue;
      }
      auto ip = reinterpret_cast<const struct ip *>(p + sizeof(ether_header));
      if (ip->ip_v != 4) {
        ++stats.skipped;
        continue;
      }
      if (ip->ip_p != IPPROTO_UDP) {
        ++stats.skipped;
        continue;
      }
      auto udp = reinterpret_cast<const udphdr *>(p + sizeof(ether_header) +
                                                  ip->ip_hl * 4);
      if (interval != -1) {
        // Use constant packet rate
        deadline.tv_sec += interval / 1000000LL;
        deadline.tv_nsec += (interval * 1000LL) % NANOSECONDS_PER_SECOND;
      } else {
        // Next packet deadline = start + (packet ts - first packet ts) * speed
        int64_t delta =
            (header.ts.tv_sec - pcap_start.tv_sec) * NANOSECONDS_PER_SECOND +
            (header.ts.tv_usec -
             pcap_start.tv_nsec); // Note PCAP_TSTAMP_PRECISION_NANO
        if (speed != 1.0) {
          delta *= speed;
        }
        deadline = start;
        deadline.tv_sec += delta / NANOSECONDS_PER_SECOND;
        deadline.tv_nsec += delta % NANOSECONDS_PER_SECOND;
      }

      // Normalize timespec
      if (deadline.tv_nsec > NANOSECONDS_PER_SECOND) {
        deadline.tv_sec++;
        deadline.tv_nsec -= NANOSECONDS_PER_SECOND;
      }

      timespec now = {};
      if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
        return 1;
      }

      if (deadline.tv_sec > now.tv_sec ||
          (deadline.tv_sec == now.tv_sec && deadline.tv_nsec > now.tv_nsec)) {
        if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline,
                            nullptr) == -1) {
          std::cerr << "clock_nanosleep: " << strerror(errno) << std::endl;
          return 1;
        }
      }

#ifdef __GLIBC__
      ssize_t len = ntohs(udp->len) - 8;
#else
      ssize_t len = ntohs(udp->uh_ulen) - 8;
#endif
      const u_char *d =
          &p[sizeof(ether_header) + ip->ip_hl * 4 + sizeof(udphdr)];

      sockaddr_in addr;
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
#ifdef __GLIBC__
      addr.sin_port = udp->dest;
#else
      addr.sin_port = udp->uh_dport;
#endif
      addr.sin_addr = {ip->ip_dst};
      auto n = sendto(fd, d, len, 0, reinterpret_cast<sockaddr *>(&addr),
                      sizeof(addr));
      if (n != len) {
        std::cerr << "sendto: " << strerror(errno) << std::endl;
        return 1;
      }

      ++stats.sent;
      ++packet_count;

      if (display_interval >= 0) {
        const auto elapsed = to_seconds(now) - to_seconds(display_time);
        if (elapsed >= display_interval) {
          printf("%s  pkt/s: %7d  trunc: %6lld  skipped: %6lld\n",
                 timestr(header), int(stats.sent / elapsed),
                 stats.truncated, stats.skipped);
          fflush(stdout);
          display_time = now;
          stats.reset();
        }
      }

      if (packet_count >= max_packets) {
        break;
      }
    }

    pcap_close(handle);
  }

  return 0;
}
