import logging
import time
from datetime import datetime, timedelta
from click import pass_context
from dns.rdatatype import RdataType
from dns.resolver import NXDOMAIN, NoAnswer, Resolver
from dns.message import QueryMessage


log = logging.getLogger(__name__)


@pass_context
def get_resolver(ctx) -> Resolver:
    resolver = Resolver()
    if nameservers := ctx.obj.get("nameservers"):
        resolver.nameservers = nameservers
    return resolver


def wait_for_challenges(
    dns_records: list[tuple[str, str]],
    wait_timeout: timedelta,
) -> None:
    """
    Wait for our DNS challenges to propagate.
    TODO: this should probably be switched to async operations to clean up the code.
    """
    resolver = get_resolver()
    challenges = {
        name: {"passed": False, "token": token} for name, token in dns_records
    }
    stop_time = datetime.now() + wait_timeout
    while datetime.now() < stop_time:
        for name, info in challenges.items():
            if info["passed"]:
                continue
            try:
                answers = resolver.resolve(name, rdtype=RdataType.TXT)
            except (NXDOMAIN, NoAnswer):
                continue
            for answer in answers:
                if answer.rdtype == RdataType.TXT:
                    if answer.strings[0].decode() == info["token"]:
                        challenges[name]["passed"] = True
        if all([info["passed"] for info in challenges.values()]):
            return
        time.sleep(5)
    waiting_names = ", ".join(
        [name for name, info in challenges.items() if not info["passed"]]
    )
    raise TimeoutError(
        f"Timeout expired for DNS propagation of following records: {waiting_names}."
    )


def resolve_cname(name: str) -> str:
    resolver = get_resolver()
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
            return current_name.rstrip(".")


def resolve_zone(name: str) -> str:
    """
    Climb through the domain tree until we find the SOA for the zone.
    """

    def _contains_cname(response: QueryMessage) -> bool:
        for answer in response.answer:
            if answer.rdtype == RdataType.CNAME:
                return True
        return False

    resolver = get_resolver()
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
