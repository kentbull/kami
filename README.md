# KAMI - KERI AsyncIO Muggle Implementation
KAMI aims to be a a spec-compliant KERI & ACDC implementation using Python's AsyncIO rather than HIO.

This includes everything in the the KERIpy, KERIA, and SignifyPy implementations all in one with the exception of the HIO dependency.

It is mostly a copy and paste of the aforementioned dependencies with major modifications to make it work with AsyncIO.

For ease of translating the package structures exactly mirror KERIpy, KERIA, and SignifyPy.


## Implementation notes

### Tasks

- Need to go back through and add async/await implementations for each Doer removed including:
  - app.agenting.Receiptor
  - app.agenting.WitnessReceiptor
  - app.agenting.WitnessInquisitor
  - app.agenting.WitnessPublisher
  - app.agenting.TCPMessenger
  - app.agenting.TCPStreamMessenger
  - app.agenting.HTTPMessenger
  - app.agenting.HTTPStreamMessenger
  - app.configing.ConfigerDoer
  - app.directing.Directant
  - app.directing.Reactor
  - app.directing.Directant
  - app.directing.Reactant
  - app.forqwarding.Poster
  - app.forwarding.StreamPoster
  - app.habbing.HaberyDoer
  - app.httping.Clienter (already started)
  - app.keeping.KeeperDoer
  - app.keeping.ManagerDoer
  - core.wiring.WireLogDoer
  - vdr.credentialing.Credentialer
  - vdr.credentialing.RegeryDoer
  - vdr.credentialing.Registrar

## Tools Used
- Ruff 
- MyPy

## Divergences from KERIpy, KERIA, HIO, and SignifyPy and Why

### Logging package

To resolve a circular import problem between `ogling -> kering -> helping -> ogling` the 
logging (ogling) package was moved to its own package. 