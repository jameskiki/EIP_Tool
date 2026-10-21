# Project context

## Future PROFIBUS support

- The app serves multiple field-device types. Keep future protocol support in
  mind when changing device handling, without implementing or refactoring for
  PROFIBUS until requested. Preserve existing EtherNet/IP behavior.
- Planned connection: laptop -> Ethernet -> Hilscher NL 51N-DPL -> PROFIBUS
  device(s). This is not a directly attached PROFIBUS adapter or an assumption
  that the downstream devices speak EtherNet/IP.
- This is an isolated bench setup. The laptop is intended to act as the
  PROFIBUS master, with the devices under test and optionally network equipment
  such as Ethernet switches; no production PLC/master is expected.
- Desired future operations: read/write I/O data, read/write device
  configuration, and read diagnostics.
- The user tentatively identifies the existing tools as Hilscher Ethernet
  Device Configurator and "Profinetmaster" software. Exact software names,
  drivers, gateway interface/API, and supported master operations are
  unconfirmed. Clarify these before implementation; do not equate PROFINET
  with PROFIBUS or assume the gateway is a transparent protocol converter.
