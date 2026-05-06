#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UiStatusLine {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LiveUiModel {
    pub header: Vec<UiStatusLine>,
    pub recent_instructions: Vec<String>,
    pub recent_artifacts: Vec<String>,
}
