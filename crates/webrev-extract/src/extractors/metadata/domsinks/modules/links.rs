//! Re-exports: `export {a as b} from './m.js'` and `export * from './m.js'`.
//! `export * as ns from` and the default specifier form stay unmodeled.
use super::{
    export_name, exported_locals, resolve, BTreeMap, BTreeSet, ExportValue, Exports, ModuleDecl,
    ModuleItem, ParsedModule,
};
use swc_core::ecma::ast::ExportSpecifier;

/// The value as seen from the re-exporting module: unchanged, with that module
/// added to the evidence so the barrel file appears in the finding's provenance.
fn through(value: &ExportValue, parsed: &ParsedModule) -> ExportValue {
    let mut value = value.clone();
    let barrel = parsed.url.to_string();
    if let Some(function) = &mut value.function {
        function.locations.insert(barrel.clone());
    }
    value.locations.insert(barrel);
    value
}

/// Names the module declares itself; they hide any re-exported name.
fn own_names(parsed: &ParsedModule) -> BTreeSet<String> {
    let mut names: BTreeSet<_> = exported_locals(&parsed.module)
        .into_iter()
        .map(|(exported, _)| exported)
        .collect();
    names.insert("default".to_owned());
    names
}

pub(super) fn named_reexports(
    parsed: &ParsedModule,
    exports: &Exports,
) -> BTreeMap<String, ExportValue> {
    let own = own_names(parsed);
    let mut result = BTreeMap::new();
    for item in &parsed.module.body {
        let ModuleItem::ModuleDecl(ModuleDecl::ExportNamed(named)) = item else {
            continue;
        };
        let Some(source) = &named.src else {
            continue;
        };
        if named.type_only || named.with.is_some() {
            continue;
        }
        let Some(url) = resolve(&parsed.url, &source.value.to_string_lossy()) else {
            continue;
        };
        for specifier in &named.specifiers {
            let ExportSpecifier::Named(specifier) = specifier else {
                continue;
            };
            if specifier.is_type_only {
                continue;
            }
            let original = export_name(&specifier.orig);
            let alias = specifier
                .exported
                .as_ref()
                .map_or_else(|| original.clone(), export_name);
            if own.contains(&alias) && alias != "default" {
                continue;
            }
            if let Some(value) = exports.get(&(url.clone(), original)) {
                result.insert(alias, through(value, parsed));
            }
        }
    }
    result
}

/// `export *` forwards every named export except `default`. A name that two
/// star exports provide with different values is ambiguous and is not exported.
pub(super) fn star_reexports(
    parsed: &ParsedModule,
    exports: &Exports,
) -> BTreeMap<String, ExportValue> {
    let own = own_names(parsed);
    let mut stars: BTreeMap<String, Option<ExportValue>> = BTreeMap::new();
    for item in &parsed.module.body {
        let ModuleItem::ModuleDecl(ModuleDecl::ExportAll(all)) = item else {
            continue;
        };
        if all.type_only || all.with.is_some() {
            continue;
        }
        let Some(url) = resolve(&parsed.url, &all.src.value.to_string_lossy()) else {
            continue;
        };
        let members = exports
            .range((url.clone(), String::new())..)
            .take_while(|((module, _), _)| *module == url);
        for ((_, name), value) in members {
            if own.contains(name) {
                continue;
            }
            let value = through(value, parsed);
            match stars.get_mut(name) {
                Some(slot) if slot.as_ref() != Some(&value) => *slot = None,
                Some(_) => {}
                None => {
                    stars.insert(name.clone(), Some(value));
                }
            }
        }
    }
    stars
        .into_iter()
        .filter_map(|(name, value)| Some((name, value?)))
        .collect()
}
