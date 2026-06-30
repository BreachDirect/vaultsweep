import re

from vaultsweep.models import Severity
from vaultsweep.rules.base import RegexRule, RuleMeta

# Common BIP39 words subset for detection — full 12+ word sequences
_BIP39_FRAGMENT = (
    r"\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|"
    r"accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|"
    r"actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|"
    r"affair|afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|"
    r"alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|also|alter|always|"
    r"amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|angry|animal|"
    r"ankle|announce|annual|another|answer|antenna|antique|anxiety|any|apart|apology|appear|"
    r"apple|approve|april|arch|arctic|area|arena|argue|arm|armed|armor|army|around|arrange|"
    r"arrest|arrive|arrow|art|artefact|artist|artwork|ask|aspect|assault|asset|assist|assume|"
    r"asthma|athlete|atom|attack|attend|attitude|attract|auction|audit|august|aunt|author|"
    r"auto|autumn|average|avocado|avoid|awake|aware|away|awesome|awful|awkward|axis|baby|"
    r"bachelor|bacon|badge|bag|balance|balcony|ball|bamboo|banana|banner|bar|barely|bargain|"
    r"barrel|base|basic|basket|battle|beach|bean|beauty|because|become|beef|before|begin|behave|"
    r"behind|believe|below|belt|bench|benefit|best|betray|better|between|beyond|bicycle|bid|"
    r"bike|bind|biology|bird|birth|bitter|black|blade|blame|blanket|blast|bleak|bless|blind|"
    r"blood|blossom|blouse|blue|blur|blush|board|boat|body|boil|bomb|bone|bonus|book|boost|"
    r"border|boring|borrow|boss|bottom|bounce|box|boy|bracket|brain|brand|brass|brave|bread|"
    r"breeze|brick|bridge|brief|bright|bring|brisk|broccoli|broken|bronze|broom|brother|brown|"
    r"brush|bubble|buddy|budget|buffalo|build|bulb|bulk|bullet|bundle|bunker|burden|burger|"
    r"burst|bus|business|busy|butter|buyer|buzz)\b"
)

# 12+ consecutive bip39-like words
_MNEMONIC = re.compile(
    rf"(?:{_BIP39_FRAGMENT}\s+){{11,}}{_BIP39_FRAGMENT}",
    re.IGNORECASE,
)


class MnemonicPhraseRule(RegexRule):
    meta = RuleMeta(
        rule_id="MNEMONIC-001",
        name="BIP39 Mnemonic Phrase Exposed",
        severity=Severity.CRITICAL,
        description="A 12+ word BIP39-style mnemonic seed phrase was found in source.",
        remediation="Never store seed phrases in code. Use hardware wallets or encrypted vaults.",
    )
    pattern = _MNEMONIC

    def _is_false_positive(self, line: str, matched: str) -> bool:
        if super()._is_false_positive(line, matched):
            return True
        words = matched.lower().split()
        if len(words) < 12:
            return True
        return False
