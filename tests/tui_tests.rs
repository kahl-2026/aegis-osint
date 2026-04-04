use aegis_osint::cli::menu::{
    DefensiveMenuOption, MainMenuOption, Menu, OffensiveMenuOption, ScopeMenuOption,
    SettingsMenuOption,
};
use std::collections::HashSet;
use std::mem::discriminant;

#[test]
fn test_menu_can_be_constructed() {
    let _menu = Menu::new();
    let _default_menu = Menu::default();
}

#[test]
fn test_main_menu_variants_are_unique() {
    let variants = [
        MainMenuOption::OffensiveMode,
        MainMenuOption::DefensiveMode,
        MainMenuOption::ManageScopes,
        MainMenuOption::ViewFindings,
        MainMenuOption::GenerateReports,
        MainMenuOption::ManageAssets,
        MainMenuOption::Settings,
        MainMenuOption::Help,
        MainMenuOption::Quit,
    ];

    let unique: HashSet<_> = variants.iter().map(discriminant).collect();
    assert_eq!(variants.len(), unique.len());
}

#[test]
fn test_submenu_variants_are_unique() {
    let offensive = [
        OffensiveMenuOption::RunRecon,
        OffensiveMenuOption::ViewStatus,
        OffensiveMenuOption::StopScan,
        OffensiveMenuOption::ViewResults,
        OffensiveMenuOption::Back,
    ];
    let defensive = [
        DefensiveMenuOption::StartMonitor,
        DefensiveMenuOption::StopMonitor,
        DefensiveMenuOption::ViewAlerts,
        DefensiveMenuOption::ConfigureAlerts,
        DefensiveMenuOption::Back,
    ];
    let scope = [
        ScopeMenuOption::ImportScope,
        ScopeMenuOption::CreateScope,
        ScopeMenuOption::AddTarget,
        ScopeMenuOption::ListScopes,
        ScopeMenuOption::ViewScope,
        ScopeMenuOption::ValidateTarget,
        ScopeMenuOption::DeleteScope,
        ScopeMenuOption::Back,
    ];
    let settings = [
        SettingsMenuOption::ViewSettings,
        SettingsMenuOption::EditRateLimit,
        SettingsMenuOption::EditTimeout,
        SettingsMenuOption::EditUserAgent,
        SettingsMenuOption::EditDatabase,
        SettingsMenuOption::ResetDefaults,
        SettingsMenuOption::Back,
    ];

    let offensive_unique: HashSet<_> = offensive.iter().map(discriminant).collect();
    let defensive_unique: HashSet<_> = defensive.iter().map(discriminant).collect();
    let scope_unique: HashSet<_> = scope.iter().map(discriminant).collect();
    let settings_unique: HashSet<_> = settings.iter().map(discriminant).collect();

    assert_eq!(offensive.len(), offensive_unique.len());
    assert_eq!(defensive.len(), defensive_unique.len());
    assert_eq!(scope.len(), scope_unique.len());
    assert_eq!(settings.len(), settings_unique.len());
}
