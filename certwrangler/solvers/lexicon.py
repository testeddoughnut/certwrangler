import logging
from dataclasses import field
from typing import Dict
from marshmallow_dataclass import dataclass
from lexicon.client import Client
from lexicon.config import ConfigResolver
from certwrangler.models import Solver, SolverDriver


log = logging.getLogger(__name__)


@dataclass
class LexiconSolver(SolverDriver):
    """Solver powered by lexicon"""

    provider_name: str = field(metadata={"required": True})
    provider_options: dict = field(default_factory=dict)

    def initialize(self, parent: Solver) -> None:
        self.parent = parent

    def create(self, name: str, domain: str, content: str) -> None:
        log.info(
            f"Solver '{self.parent.name}' creating TXT '{name}' zone '{domain}' - '{content}'..."
        )
        config_dict = self._build_config("create", name, domain, content)
        lexicon_config = ConfigResolver().with_dict(config_dict)
        Client(lexicon_config).execute()

    def delete(self, name: str, domain: str, content: str) -> None:
        log.info(
            f"Solver '{self.parent.name}' deleting TXT '{name}' zone '{domain}' - '{content}'..."
        )
        config_dict = self._build_config("delete", name, domain, content)
        lexicon_config = ConfigResolver().with_dict(config_dict)
        Client(lexicon_config).execute()

    def _build_config(self, action: str, name: str, domain: str, content: str) -> Dict:
        return {
            "action": action,
            "name": name,
            "domain": domain,
            "delegated": domain,
            "type": "TXT",
            "content": content,
            "provider_name": self.provider_name,
            self.provider_name: self.provider_options,
        }
