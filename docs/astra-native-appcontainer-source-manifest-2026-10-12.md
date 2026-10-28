# Astra Native/AppContainer Source Closure Manifest

> Read-only snapshot: 2026-10-12. This is provenance evidence, not an approval.
> The working tree is dirty; these hashes describe the files as read at snapshot time.

## Security-relevant source and build inputs

| Path | SHA-256 | Git state |
|---|---|---|
| `third-party/codex-security-poc/native_appcontainer_launcher.c` | `DA66889D38F5D82B78D5AE0134FA8F96FF2AF44E011242F7A35EDF8EA4861081` | untracked |
| `src/openjarvis/sandbox/appcontainer.py` | `85F2503902FA4A6CA45E2422F7AFE0954CC4E41F0EB8727F4C61CA7721393318` | untracked |
| `src/openjarvis/sandbox/staged_runtime.py` | `300D7FBE5179CE8EDCC361C1DFE179949B5D1AC8475A8C3CE0F9516DDD88E3A1` | untracked |
| `src/openjarvis/sandbox/worker_launcher.py` | `CD3FF2A051837D9327D10D78818B94B20A1309CD62B4FAEDA7DADDDB1B5D907F` | untracked |
| `src/openjarvis/sandbox/mount_security.py` | `6D14C72C17D6B249E2934E65ADC118CB48EACF511ABBD5CB5C8DFEB384CED78F` | tracked-clean |
| `src/openjarvis/sandbox/runner.py` | `9D6556BC43041C6EA333BDE1C7D781E761DB42781C2BDDD910369E437429C4F7` | tracked-clean |
| `src/openjarvis/_rust_bridge.py` | `C3CA000C074401E6670777FECC7B8930BF890A90BED6B25D2C00671226D50F91` | tracked-clean |
| `rust/crates/openjarvis-python/src/lib.rs` | `F209DD42E67E3F7B8C9033239CC3F8EC8E2E6E69E897E0BE2CC92C412BE3068F` | tracked-clean |
| `rust/Cargo.toml` | `9D02C00B346EFFAA37C0A74693680023A6520C876DEE03016BD056ABB0E52824` | tracked-clean |
| `rust/Cargo.lock` | `69FD237228010090C155FF455E06595A60818483C089ACF8CE09A7A349ADA6A5` | tracked-clean |
| `rust/rust-toolchain.toml` | `911CC011D5639DB886F4E83F20A980C10B5D213D3307D3C4BFCB74721E4902B5` | tracked-clean |
| `rust/crates/openjarvis-python/Cargo.toml` | `0C39EAEEB3F702B42F04B13EB55B925572E28A063AC69F99551161BD93853B6B` | tracked-clean |
| `rust/crates/openjarvis-python/pyproject.toml` | `E775EE16E00C79BEAAA60AC6FA17146CCD57EA09EDE38CCD750ACFE36F9B813D` | tracked-clean |

The AppContainer Python launcher files and the diagnostic C launcher are currently
untracked. Therefore the branch HEAD does not uniquely identify those bytes.
The Rust manifests and binding are tracked and clean in the current checkout.

## Rust extension dependency closure

The ignored dependency file
`rust/target/debug/openjarvis_rust.d` enumerated **124** Rust source
files for the existing debug DLL. The complete per-file hash list follows. This
is a source-closure record for that DLL; it does not prove that the DLL was built
from this exact tree or with the pinned toolchain.

| Rust source path | SHA-256 | Git state |
|---|---|---|
| `rust/crates/openjarvis-a2a/src/lib.rs` | `E9CB13D4AA6346E2C94DC5E0C9A7F66D8F5784916C969EE3D6F6AC7F516E11E4` | tracked, clean |
| `rust/crates/openjarvis-agents/src/helpers.rs` | `B757C5555302AA86937DCC87545559DF00E1007073928EB39B6E843B34062354` | tracked, clean |
| `rust/crates/openjarvis-agents/src/lib.rs` | `B7E50BAD296C6A8F8A3575BC77C602663E42AE779AA77C3F824A90CA0036392E` | tracked, clean |
| `rust/crates/openjarvis-agents/src/loop_guard.rs` | `D14C65D0C9D59B4F4880C4957BF70BE0A54BA14145ED0050C5D61659C9718AB9` | tracked, clean |
| `rust/crates/openjarvis-agents/src/monitor_operative.rs` | `B4A29372666D9D944415502C46032D66413C64F90496034D558A92D2DCBB6252` | tracked, clean |
| `rust/crates/openjarvis-agents/src/native_openhands.rs` | `9D7253634C87721905D6F065ECACD8F5F144D4DB9D92D29208B6FD3D62D6A007` | tracked, clean |
| `rust/crates/openjarvis-agents/src/native_react.rs` | `CDEDEFE36E2F3D7ADC483A25BB6B744FBDC0DCA529CFFF67C24C06C06B4F8BB2` | tracked, clean |
| `rust/crates/openjarvis-agents/src/orchestrator.rs` | `42EAF453A179DA116D366366721006CDDD466D7E2DC5B1AC4A8F4C0DD391E5D8` | tracked, clean |
| `rust/crates/openjarvis-agents/src/simple.rs` | `00A1F59706362FFFE584ADC53118C655FD7C4703987752F111579B6A377B9688` | tracked, clean |
| `rust/crates/openjarvis-agents/src/traits.rs` | `D418F7151E69D612D67C194D99056D93DE22045FCFE8EBDF2480F85584783808` | tracked, clean |
| `rust/crates/openjarvis-agents/src/utils.rs` | `72F7430AE81E4FB17C1B2748B569FD6F3C5F9BC400630C52F87AD7C33A31934C` | tracked, clean |
| `rust/crates/openjarvis-core/src/config.rs` | `32167544F07B691103019E8F6A03B1243C7F51813F445B1ABD8CB1773B44B88E` | tracked, clean |
| `rust/crates/openjarvis-core/src/error.rs` | `E0CFF4801481D0455137EEEAE2DB7A57D42384D49F9D8D61BDC40B80C9C47D0A` | tracked, clean |
| `rust/crates/openjarvis-core/src/events.rs` | `BBA6B23ABF876B6F40D39E53F888445F2F5DA3F1C87F267B940807AD34C63283` | tracked, clean |
| `rust/crates/openjarvis-core/src/hardware.rs` | `5DF8F0D8CA5DC4A768D81EE287394CA426E11176C933ECE728608A1087F0BE4F` | tracked, clean |
| `rust/crates/openjarvis-core/src/lib.rs` | `8123E2A560EBF6B9B0BF7F3E5DA143519E5559B3FD4E739A399E74015AE73C1D` | tracked, clean |
| `rust/crates/openjarvis-core/src/model_catalog.rs` | `58A460165B57AFAE71615667D2BB87BD0B1D2E526BAC967BEF62116892A62D27` | tracked, clean |
| `rust/crates/openjarvis-core/src/registry.rs` | `19A05F6FCE9965F70FA31C7D942739527D75F7858889927494BA67F0DEB12F4B` | tracked, clean |
| `rust/crates/openjarvis-core/src/types.rs` | `AFCA6B46764D3682E1034F071476CFC5140408AC1750B6527B7BFA001645976C` | tracked, clean |
| `rust/crates/openjarvis-engine/src/discovery.rs` | `ECA8182BC35784F6BE1FFE9B7A2E32F430E390894B92081A1975824FB655E062` | tracked, clean |
| `rust/crates/openjarvis-engine/src/engine_enum.rs` | `5C1FEFC177A46302290633D396648853CF30A6FBA1FDA9F46B3EE950F05F18C0` | tracked, clean |
| `rust/crates/openjarvis-engine/src/lib.rs` | `BED1E42421FFE6B726626837BB1C97916D2014832A1793AD7B4DF4058BAB7889` | tracked, clean |
| `rust/crates/openjarvis-engine/src/llamacpp.rs` | `A8378EE3C3774B6265B5D2C46CA531839E3CF6C974D035F71624177C48133E81` | tracked, clean |
| `rust/crates/openjarvis-engine/src/ollama.rs` | `A153FF144A29B63A08401DE060F44000F1856C65A563C3E0476A8A05CF26233A` | tracked, clean |
| `rust/crates/openjarvis-engine/src/openai_compat.rs` | `85E5A94286A9EF8993909991E621A710E7E5022D5E36ACEE1746C1BC642678DD` | tracked, clean |
| `rust/crates/openjarvis-engine/src/rig_adapter.rs` | `6382A4602763F3577BCC52EF79DBD302F3ECCE67AC2758E0D7DF35A9076E1056` | tracked, clean |
| `rust/crates/openjarvis-engine/src/sglang.rs` | `B370BE0CCCE3A26680F8796F966B93EBB029B39CF73C0563D4D060DDE13629D3` | tracked, clean |
| `rust/crates/openjarvis-engine/src/traits.rs` | `4F5A263EB145E955F29F31A177AC323594A4310CA035177F84EA3FDF39B28D23` | tracked, clean |
| `rust/crates/openjarvis-engine/src/vllm.rs` | `46D4D973330BEF816A31806BD525EF3588C79E08CCF46B60F48176E26E2C6980` | tracked, clean |
| `rust/crates/openjarvis-learning/src/agent_advisor.rs` | `F10CEBF1C8AEFB6FE5A82114E49392A7593BA4B094A8A80571ABB28C9EB26970` | tracked, clean |
| `rust/crates/openjarvis-learning/src/agent_evolver.rs` | `7E61FBC93B803B7D422F7B6C46CB96D409A62F59F4A6316176592F02923A774A` | tracked, clean |
| `rust/crates/openjarvis-learning/src/bandit.rs` | `711FC2475FF5CEDB61224030A7200B512915CFFA08926DC03BF91DA51013888F` | tracked, clean |
| `rust/crates/openjarvis-learning/src/grpo.rs` | `E59CBE7F1B147CD816291A4D15A808BE6C2E66235C8605DB645B22BA828467AB` | tracked, clean |
| `rust/crates/openjarvis-learning/src/heuristic_reward.rs` | `B92F621BC18FD8F44C152C0A04C84C15985B33E5E2A6880BE5DA3A738C5BA542` | tracked, clean |
| `rust/crates/openjarvis-learning/src/heuristic.rs` | `A9EC42F929E16BB5267D51FAD76D3100732CB8B64B1718CAA85BA09199CF3383` | tracked, clean |
| `rust/crates/openjarvis-learning/src/icl_updater.rs` | `3A29601674B434E4B6E29FE8779569B724C9BBC4EE67ACE2DEE9F47F48ACDD4C` | tracked, clean |
| `rust/crates/openjarvis-learning/src/learning_orchestrator.rs` | `E6C9AE5521F895EB84CBF67AA1CE52AA015EA471646A6AFD0F819D1712612151` | tracked, clean |
| `rust/crates/openjarvis-learning/src/lib.rs` | `D1C323AC976BBAEC4910FAEF83708799DF55BC6767E51AACA214B5645E7FEF1B` | tracked, clean |
| `rust/crates/openjarvis-learning/src/optimize/engine.rs` | `077EE3F54797365ABA18D4EFFCF2B5F342D83C4AAE6AA53872F90286CA2B4FDD` | tracked, clean |
| `rust/crates/openjarvis-learning/src/optimize/llm_optimizer.rs` | `D242BADA0941AE7C2B4639CAC06E1F62F37F247487D27A6230A6AA6AA92C6735` | tracked, clean |
| `rust/crates/openjarvis-learning/src/optimize/mod.rs` | `EA4B61B3D954154CC6DF478C4E11E4C839A1D328EAB1CFB6C48F53BCD6B9D08F` | tracked, clean |
| `rust/crates/openjarvis-learning/src/optimize/search_space.rs` | `F8CACF1BAEDF17A2B4F42815C68CEB37B9792FE5FC5DA7846032C8EA88EE4479` | tracked, clean |
| `rust/crates/openjarvis-learning/src/optimize/store.rs` | `37187A92973ADCD4C9137D0DE461589881CF79BE5210EC4B8BA8D06069ED2A6E` | tracked, clean |
| `rust/crates/openjarvis-learning/src/optimize/types.rs` | `0C47179E8DA3D17163045AE45E2E43E817F86BD6BAF10F83B64ED072FEA59EFD` | tracked, clean |
| `rust/crates/openjarvis-learning/src/orchestrator_types.rs` | `CF4DAED2BDCB8E07AE1A330E91989D0487036EE563EF477E66A769AAE9AE5A2C` | tracked, clean |
| `rust/crates/openjarvis-learning/src/reward.rs` | `AA2DA620A099076AD3F41E15639D4E810A51013E03DBFB6D1CDDD24F99C88641` | tracked, clean |
| `rust/crates/openjarvis-learning/src/router_enum.rs` | `B194DA5BEA17C12FB259662D6373BE4D38E2FC90BBDF9DC9A2EDE5F0F166BE25` | tracked, clean |
| `rust/crates/openjarvis-learning/src/sft_policy.rs` | `19154888F33874061DF974227451E6982CF588E1E9C5A44EED957141BF310735` | tracked, clean |
| `rust/crates/openjarvis-learning/src/skill_discovery.rs` | `976EAE461BB79C88A738228BB866402AAE0CA0266E1A2F215828711EFA4BE638` | tracked, clean |
| `rust/crates/openjarvis-learning/src/trace_policy.rs` | `F6C98985DD8B6095C2E810C5599F54A2AD023A512185A0349029F723075FE98E` | tracked, clean |
| `rust/crates/openjarvis-learning/src/training_data.rs` | `F11AAA573048B074F0F7E0E72FF85567BF0E6FE5BB9AA1457414F12BF6865728` | tracked, clean |
| `rust/crates/openjarvis-learning/src/traits.rs` | `6C43522363A6AED4524D66DD2AE212C2DD6CD96AECA60C3CA86C6E7CB607857C` | tracked, clean |
| `rust/crates/openjarvis-mcp/src/lib.rs` | `A440EA5BBCC4EB2276013F98C689290D2312339591751BE1115CE72905FC0756` | tracked, clean |
| `rust/crates/openjarvis-mcp/src/protocol.rs` | `BC50618F65152D9AEE1E9A2A2E3674448BFC5DC126B56A1B9953D9A3EDA96DFC` | tracked, clean |
| `rust/crates/openjarvis-mcp/src/server.rs` | `1761138156F517EDD64156AE047F991E9911A1F7F9F91C37653A6F7DEDD32EED` | tracked, clean |
| `rust/crates/openjarvis-python/src/a2a.rs` | `A9B3654608ACB4C4DC13A50F783EECAF602DC9D33521F539A4731CB5A6EDD9B1` | tracked, clean |
| `rust/crates/openjarvis-python/src/agents.rs` | `38D23C4F1A43467EF9A5B0676AF18C89A6E9CEE1C0B919742F3C6A68C8252826` | tracked, clean |
| `rust/crates/openjarvis-python/src/core.rs` | `1501223714F852785C487E5831A319E8EA7A6B55EBE3C1DFA61A786154AE75E6` | tracked, clean |
| `rust/crates/openjarvis-python/src/engine.rs` | `F9C126F50158A05ECCB24600B1D44E3E4C736825DE01DE133699C1805BDBBEF8` | tracked, clean |
| `rust/crates/openjarvis-python/src/learning.rs` | `C6F5D05F4E497AD0458DFB2C5A2E550AD141FE2099405CF4921DA04013E5ED5C` | tracked, clean |
| `rust/crates/openjarvis-python/src/lib.rs` | `F209DD42E67E3F7B8C9033239CC3F8EC8E2E6E69E897E0BE2CC92C412BE3068F` | tracked, clean |
| `rust/crates/openjarvis-python/src/mcp.rs` | `BCA18E29250438A80D2E8874FBBD18EF4897EC7520827F1E957D1C7053F7F10E` | tracked, clean |
| `rust/crates/openjarvis-python/src/recipes.rs` | `BA22651BF779A1E93EFBEAB8CFF8B8D3F67C2716001365B2C92FB88A81D91348` | tracked, clean |
| `rust/crates/openjarvis-python/src/scheduler.rs` | `C134A0E8FF06178D9B9FA6FA9D2C8DD5642BA5AB753A411D8A0DA690EB22C070` | tracked, clean |
| `rust/crates/openjarvis-python/src/security.rs` | `B23D6FFEE4C51EA56A141EF0E7785B65684ADEF2ED3CD4C0B4912BB4688503E6` | tracked, clean |
| `rust/crates/openjarvis-python/src/sessions.rs` | `61BAF0C0797CF9F6C544C51B1732153AEDC96D7FA194A7C782316EA476E80470` | tracked, clean |
| `rust/crates/openjarvis-python/src/skills.rs` | `0385D87D71345B46E05410EB0A3948428663495BB014F7C34E61FA795E7230AA` | tracked, clean |
| `rust/crates/openjarvis-python/src/storage.rs` | `DD5C369B966699C7A86AF4867FEFE68A4B4F766555A245E0294925F3EEF0340F` | tracked, clean |
| `rust/crates/openjarvis-python/src/telemetry.rs` | `38D88F7DB00F8E6A2CA830B90B88BD52451FC5A227DCB0728869C6749BC213AD` | tracked, clean |
| `rust/crates/openjarvis-python/src/templates.rs` | `A21CA0B49074DEFFFE224EFFC0F5D089E2E2E5571D0EAFBE7C90F3F40D09F9CC` | tracked, clean |
| `rust/crates/openjarvis-python/src/tools.rs` | `E8C981570C092591FDDE2A6657433491DA7692D6E3E6501E3C3F7D2E5FA0FF43` | tracked, clean |
| `rust/crates/openjarvis-python/src/traces.rs` | `28F8F80A8E83496FB46C637A7CB4ECB1D7D0E84FA2C3A362DE0758A3AA033350` | tracked, clean |
| `rust/crates/openjarvis-python/src/workflow.rs` | `8EE26D8EA2DA9FF370D030B1FF5FE8BBE8F11E123C8C7BC247BD5CCB53976586` | tracked, clean |
| `rust/crates/openjarvis-recipes/src/lib.rs` | `91FCFA51232840B01C8C36BE111BB4520C00BFB2D858CCEE78581347D7CC47BE` | tracked, clean |
| `rust/crates/openjarvis-scheduler/src/lib.rs` | `B4DABE9814EDECA6FAEA8D17C0B1AA518307FB541A7C8D310304D1740D6960F1` | tracked, clean |
| `rust/crates/openjarvis-security/src/audit.rs` | `74D484103B47F8F1C756AF41125F2CA19DEC88AE45FB2B3973D55ACB316A4D07` | tracked, clean |
| `rust/crates/openjarvis-security/src/capabilities.rs` | `68E8C51566F6E9A9EEE0B826AEF4914FAEF9C0FCAEB252C85D3A3C3A7A9DB308` | tracked, clean |
| `rust/crates/openjarvis-security/src/file_policy.rs` | `9636078BD842F70F69AE439EF03722EC2299A510889BA99FD9FFAA3E87544E0A` | tracked, clean |
| `rust/crates/openjarvis-security/src/guardrails.rs` | `4CF9C817192D795922F3DDD2C29F87D966A21E1DC6D517104F9FC2328D00AD1B` | tracked, clean |
| `rust/crates/openjarvis-security/src/injection.rs` | `7AEA5DD65D522968FDA1ACF4371AE671C3999612793A4AEFA9B5310D0D3C5464` | tracked, clean |
| `rust/crates/openjarvis-security/src/lib.rs` | `4D024A1C6431B71CFC1109EBFEA8A69AF194DA3CAA962504E38912DBBEF41308` | tracked, clean |
| `rust/crates/openjarvis-security/src/rate_limiter.rs` | `AB2C79D46B66F050ED6A6CA22C0B3BB27EEDA271BBC3F9D5311BB9968AD7FAF9` | tracked, clean |
| `rust/crates/openjarvis-security/src/scanner.rs` | `0B6EE074D7C750F7807AD0F1791FC5CE727834C8312AB0E8B66A2FFBD6927A05` | tracked, clean |
| `rust/crates/openjarvis-security/src/ssrf.rs` | `FA4FF2B5904E2DA13773BF56253368AB7C311B7858D72D54169935CD505F2BD0` | tracked, clean |
| `rust/crates/openjarvis-security/src/taint.rs` | `C5FCC8BE8850AB520F33677568F23915902269D19CE1D85F49AB5B950B741142` | tracked, clean |
| `rust/crates/openjarvis-security/src/types.rs` | `525EBAE902E95CFCE2BE8739DA357E8643FE6F9CCFD1F28DDE447D731815C4A6` | tracked, clean |
| `rust/crates/openjarvis-sessions/src/lib.rs` | `8A7CA2B387DD682FE2C4337A50F0E9AF79E9A9FD3E73541D54C46BE504262F1B` | tracked, clean |
| `rust/crates/openjarvis-skills/src/lib.rs` | `34D16508E060AE66A7BADCDC3B860B3E57865E495FBD9682B8160900F2C2A159` | tracked, clean |
| `rust/crates/openjarvis-telemetry/src/aggregator.rs` | `896EB18E55F56BE56B10FB210F9B81B7C177D9CC841C542AD783BCC317D0BE1E` | tracked, clean |
| `rust/crates/openjarvis-telemetry/src/energy.rs` | `88ECFBA3AE113080F0B0C0BA8B6A4AA9E456E5FE6C729616350297B8F2FFE571` | tracked, clean |
| `rust/crates/openjarvis-telemetry/src/flops.rs` | `24AD0D65CAC4BAB8E15B9B14BFA4C7192CF428FEFC99E06BF4D24CC1207A1567` | tracked, clean |
| `rust/crates/openjarvis-telemetry/src/instrumented.rs` | `B1A2A4E5AAA5A5567C6703072B2C5D7B25C2428E5DFA78975C529199E1BE798D` | tracked, clean |
| `rust/crates/openjarvis-telemetry/src/itl.rs` | `3E3274E8D3B4C43B9756D098573AEA0D3D44C73BFCBC7F68D53858314562A797` | tracked, clean |
| `rust/crates/openjarvis-telemetry/src/lib.rs` | `54C1C98153BD78CE57DE23378A402AFC26FD2196C41E8C684BE7BCCEF71BCAD9` | tracked, clean |
| `rust/crates/openjarvis-telemetry/src/phase.rs` | `1CDEE81DD535289E123348481E712C418D16AFFFF584EC77AF6DE36427CA8F20` | tracked, clean |
| `rust/crates/openjarvis-telemetry/src/session.rs` | `9C728769E995619970659D5882E8D0BEE428DCBA44DE2CF77F6EEE8BBAA74CE2` | tracked, clean |
| `rust/crates/openjarvis-telemetry/src/store.rs` | `9AE839A960A1F2C798149336765A2E4A552E070C818967A14F53B4BD0D0BC030` | tracked, clean |
| `rust/crates/openjarvis-templates/src/lib.rs` | `1DD714CDD3F9CC840541161DDF0E605E6B116D81EBC4ECD911D2717E1CD494FE` | tracked, clean |
| `rust/crates/openjarvis-tools/src/builtin/calculator.rs` | `5206C0D12BC84455369B337856BE9B914ACDAA032C7757190AC353796E3D9F73` | tracked, clean |
| `rust/crates/openjarvis-tools/src/builtin/file_tools.rs` | `18EEF7EFDD1DB8F1192933B2BE6D436F866CDA0326405C36314C797A1F5C4993` | tracked, clean |
| `rust/crates/openjarvis-tools/src/builtin/git_tools.rs` | `93398752D0EBB6587ADB9E93928BF49130BD5473BB8209CBA857AC86E994D1A8` | tracked, clean |
| `rust/crates/openjarvis-tools/src/builtin/http_tools.rs` | `753F2EF108C52A4996CD516C392F21E2E713A23FAF88581CF2DC0914F2B14875` | tracked, clean |
| `rust/crates/openjarvis-tools/src/builtin/mod.rs` | `7BF272A732572E9C907B12263012D2927D762D58D27794A92C235AF0F313EBE9` | tracked, clean |
| `rust/crates/openjarvis-tools/src/builtin/shell.rs` | `C898500558619EF9FEE4AAB82D7F69C9FCD48545FEE8A076DA2704956F54C067` | tracked, clean |
| `rust/crates/openjarvis-tools/src/builtin/think.rs` | `AE04B062814F76DE278C1E70CBC551588C3100DF70BF2D8BD97C2CFBC53E1C6D` | tracked, clean |
| `rust/crates/openjarvis-tools/src/executor.rs` | `6787053AC6CEF5AA7A05E8859CE30CD5E766CBC1DB937B0FA45793403A36DB21` | tracked, clean |
| `rust/crates/openjarvis-tools/src/lib.rs` | `7A98DD427229C54CF24AF0B6BF498EA85C15C19AA4292D9B31A6E3DEC0F995B3` | tracked, clean |
| `rust/crates/openjarvis-tools/src/rig_tools.rs` | `CB8270CDA90CFFC1349659639D19FDAC622C2AF84C84B3B9A12A51A640BCA75E` | tracked, clean |
| `rust/crates/openjarvis-tools/src/storage/backend_enum.rs` | `5DBFB4BFE61EFCC6E7CF580365B26EFA18431284E961A422B26B4364948D2B95` | tracked, clean |
| `rust/crates/openjarvis-tools/src/storage/bm25.rs` | `7E0900CFF0133E14F1F502F2C0020A3901466AEEE7330FE2B56FCE1A42FD4579` | tracked, clean |
| `rust/crates/openjarvis-tools/src/storage/colbert.rs` | `2230883B951EB4707432F7DAFB7B946654A4CB7418F99520C60A876E19F96351` | tracked, clean |
| `rust/crates/openjarvis-tools/src/storage/faiss.rs` | `06A339F29A93ADBCD672C419290F860F094E8A587C72FD8D1734821EAB113D57` | tracked, clean |
| `rust/crates/openjarvis-tools/src/storage/hybrid.rs` | `2296A5983C49149976ABF4B632C4C4CFDE626531057491DFD40F96A2C85A065B` | tracked, clean |
| `rust/crates/openjarvis-tools/src/storage/knowledge_graph.rs` | `8300A7515B4B2A0FA3D2C4ED1397520C1B90DA419B97751D006E94BA3078427A` | tracked, clean |
| `rust/crates/openjarvis-tools/src/storage/mod.rs` | `3A6355633EAB3EA4C54153E9CF2DBAB7E2030228FD17DB046776C7877FB9BE93` | tracked, clean |
| `rust/crates/openjarvis-tools/src/storage/sqlite.rs` | `2DD49EEFCE7C8381CF1E3FA9693B3CB0B4B8E5C3990108216D8FCDE88F59C0C5` | tracked, clean |
| `rust/crates/openjarvis-tools/src/storage/traits.rs` | `4E366DB114361982F0E7E69163D98C3531708AC5A9E8B86E03F193DAF17D6344` | tracked, clean |
| `rust/crates/openjarvis-tools/src/storage/utils.rs` | `FB7B0693C403D563892B1F99EB1C3CCE68F0EDC97ABD893A5066666D7A6D3573` | tracked, clean |
| `rust/crates/openjarvis-tools/src/traits.rs` | `73187C2A2A4106EB5F62908F45F411CB178CA009D58C9DD0B5FA9EEB120ECB08` | tracked, clean |
| `rust/crates/openjarvis-traces/src/analyzer.rs` | `D60290668A92EB2C10A1501F10AE0AABCEF2ECF790A377F703BDACBECE8F2A9A` | tracked, clean |
| `rust/crates/openjarvis-traces/src/collector.rs` | `727109C73FA2F7E536135E6F2A8EC429E1398686714FD39A964C37DD6BBF3479` | tracked, clean |
| `rust/crates/openjarvis-traces/src/lib.rs` | `63B221677A7291CAF47389C2384F7E5AF78D76E1D0DB72A53260895B7B36A5E4` | tracked, clean |
| `rust/crates/openjarvis-traces/src/store.rs` | `07C6B16DA9076233252D5CBE71BD947C5A1A23B2E5B474B7F1DC15492A27655A` | tracked, clean |
| `rust/crates/openjarvis-workflow/src/lib.rs` | `E26D172D544B27569EC2B5742E0E350C3D18CC07FF07A06BD6EEACA0EF386D00` | tracked, clean |

## Build metadata files

| Evidence | SHA-256 | State |
|---|---|---|
| `rust/target/debug/openjarvis_rust.d` | `808AFF5E5DADE158AB287BCD157FE53804D86B8EA59D69E6551ACD921CE86BE4` | ignored build output |
| `rust/target/.rustc_info.json` | `0CD4EA64F2832F414D13F88735BD36044EA3166F6C7D28E5CA9F3D87B4CFFD63` | ignored build output |
| `rust/target/debug/openjarvis_rust.dll` | `832E6629917814A518B0BB9AB1ABCB7FB45A7E0DA64A2655B8ED8004E5849888` | ignored build output; unsigned |

## Limitations

- No immutable build record links the DLL hash to a source commit, resolved
  dependency graph, flags, or signing event.
- The source closure includes the Rust workspace used by the PyO3 extension,
  not an approved AppContainer launcher.
- An approved Windows policy rule and human approval are absent.

