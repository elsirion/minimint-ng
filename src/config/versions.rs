use super::*;
pub const CORE_CONSENSUS: Version = Version { major: 2, minor: 1 };
pub const MODULE_CONSENSUS: Version = Version { major: 1, minor: 0 };
pub const CORE_API: Version = Version { major: 0, minor: 9 };
pub const MODULE_API: Version = Version { major: 0, minor: 1 };
/// Binary decoding preserves the baseline's unchecked order; JSON boundary must
/// call validate() before accepting an advertisement (VER-002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiVersions {
    pub versions: Vec<Version>,
}
record!(ApiVersions, versions);
impl ApiVersions {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.versions.windows(2).any(|w| w[0].major >= w[1].major) {
            Err(ConfigError::InvalidProfile)
        } else {
            Ok(())
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreSupport {
    pub core_consensus: Version,
    pub api: ApiVersions,
}
record!(CoreSupport, core_consensus, api);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSupport {
    pub core_consensus: Version,
    pub module_consensus: Version,
    pub api: ApiVersions,
}
record!(ModuleSupport, core_consensus, module_consensus, api);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportSummary {
    pub core: CoreSupport,
    pub modules: BTreeMap<ModuleId, ModuleSupport>,
}
record!(SupportSummary, core, modules);
impl CoreSupport {
    pub fn compatible(&self, consensus: Version, required_api: Version) -> bool {
        self.core_consensus.major == consensus.major
            && self
                .api
                .versions
                .iter()
                .any(|v| v.major == required_api.major && v.minor >= required_api.minor)
    }
}
impl ModuleSupport {
    pub fn compatible(&self, core: Version, module: Version, api: Version) -> bool {
        self.core_consensus.major == core.major
            && self.module_consensus.major == module.major
            && self
                .api
                .versions
                .iter()
                .any(|v| v.major == api.major && v.minor >= api.minor)
    }
}
pub fn normalize_release(release: &str) -> &str {
    release.split(['-', '+']).next().unwrap_or(release)
}
