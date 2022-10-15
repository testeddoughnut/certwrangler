from dns.rdatatype import RdataType
from dns.resolver import NXDOMAIN, NoAnswer, Resolver
from dns.message import QueryMessage


def get_resolver(nameservers: list[str] = None) -> Resolver:
    resolver = Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


def check_challenge(name: str, token: str, nameservers: list[str] = None) -> bool:
    pass


def resolve_cname(name: str, nameservers: list[str] = None) -> str:
    resolver = get_resolver(nameservers)
    current_name = name
    visited = [current_name]

    while True:
        try:
            answer = resolver.resolve(current_name, rdtype=RdataType.CNAME)
            current_name = str(answer[0].target)
            if current_name in visited:
                resolution_map = " -> ".join([*visited, current_name])
                raise ValueError(
                    f"Error, CNAME resolution for {current_name} ended in an infinite loop!\n"
                    f"{resolution_map}"
                )
            visited.append(current_name)
        except (NXDOMAIN, NoAnswer):
            # No more CNAME in the chain, we have the final canonical_name
            return current_name


def resolve_zone(name: str, nameservers: list[str] = None) -> str:
    """
    Climb through the domain tree until we find the SOA for the zone.
    """

    def _contains_cname(response: QueryMessage) -> bool:
        for answer in response.answer:
            if answer.rdtype == RdataType.CNAME:
                return True
        return False

    resolver = get_resolver(nameservers)
    split_name = name.rstrip(".").split(".")
    for index, _ in enumerate(split_name):
        domain = ".".join(split_name[index:])
        try:
            response = resolver.resolve(domain, rdtype=RdataType.SOA).response
        except (NXDOMAIN, NoAnswer):
            # No SOA at this level, move up and try again
            continue
        # CNAMEs can't exist at the root of a zone, continue if we have one.
        if _contains_cname(response):
            continue
        for answer in response.answer:
            if answer.rdtype == RdataType.SOA:
                return answer.name.to_text().rstrip(".")
    raise ValueError(f"Unable to find SOA in DNS tree for '{name}'")
