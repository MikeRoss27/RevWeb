use webrev_core::{Finding, FindingKind, SessionId};
use webrev_extract::{
    extractors::{
        DomSinkExtractor, JsAstExtractor, JsRegexExtractor, ParamExtractor, SecretExtractor,
    },
    ContentKind, ExtractInput, Extractor,
};

#[derive(Clone, Copy)]
struct Case {
    positive: bool,
    kind: ContentKind,
    input: &'static str,
}

fn measure(
    extractor: &dyn Extractor,
    cases: &[Case],
    predicate: impl Fn(&Finding) -> bool,
) -> (usize, usize, usize, usize) {
    let mut tp = 0;
    let mut fp = 0;
    let mut fn_ = 0;
    let mut tn = 0;
    for case in cases {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://fixture.test/app.js".into()),
            case.kind,
            case.input,
        );
        let detected = extractor.extract(&input).iter().any(&predicate);
        match (case.positive, detected) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (true, false) => fn_ += 1,
            (false, false) => tn += 1,
        }
    }
    (tp, fp, fn_, tn)
}

fn report(name: &str, (tp, fp, fn_, tn): (usize, usize, usize, usize)) {
    let precision = ratio(tp, tp + fp);
    let recall = ratio(tp, tp + fn_);
    let fpr = ratio(fp, fp + tn);
    let fnr = ratio(fn_, fn_ + tp);
    eprintln!("benchmark {name}: TP={tp} FP={fp} FN={fn_} TN={tn}; precision={precision:.3} recall={recall:.3} FPR={fpr:.3} FNR={fnr:.3}");
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[test]
fn labeled_static_detector_corpus() {
    let endpoints = [
        Case {
            positive: true,
            kind: ContentKind::JavaScript,
            input: "fetch('/api/profile')",
        },
        Case {
            positive: true,
            kind: ContentKind::JavaScript,
            input: "axios.post('/api/login', body)",
        },
        Case {
            positive: false,
            kind: ContentKind::JavaScript,
            input: "const docs = 'Use /api/profile in the example';",
        },
        Case {
            positive: false,
            kind: ContentKind::JavaScript,
            input: "const ns = 'https://www.w3.org/2000/svg';",
        },
    ];
    let is_endpoint = |f: &Finding| f.kind == FindingKind::Endpoint;
    report(
        "js_ast_endpoints",
        measure(&JsAstExtractor::new(), &endpoints, is_endpoint),
    );
    report(
        "js_regex_endpoints",
        measure(&JsRegexExtractor::new(), &endpoints, is_endpoint),
    );

    let parameters = [
        Case {
            positive: true,
            kind: ContentKind::Html,
            input: "<form><input name='email'></form>",
        },
        Case {
            positive: true,
            kind: ContentKind::JavaScript,
            input: "fetch('/api/search?q=x&page=1')",
        },
        Case {
            positive: false,
            kind: ContentKind::JavaScript,
            input: "const settings = {'internalFlag': true};",
        },
        Case {
            positive: false,
            kind: ContentKind::JavaScript,
            input: "const sample = '?debug=1';",
        },
    ];
    report(
        "http_parameters",
        measure(&ParamExtractor::new(), &parameters, |f| {
            f.kind == FindingKind::Parameter
        }),
    );

    let secrets = [
        Case { positive: true, kind: ContentKind::JavaScript, input: "const accessKey = 'AKIAZ4XB7NMPQR2STUVW';" },
        Case { positive: true, kind: ContentKind::JavaScript, input: "const apiKey = 'Rj8Kpz2Wqf4Lm9Xv7Tb3Nc6Hy1Qs5Ad';" },
        Case { positive: false, kind: ContentKind::Html, input: "<div id='Rj8Kpz2Wqf4Lm9Xv7Tb3Nc6Hy1Qs5Ad' class='sk-Rj8Kpz2Wqf4Lm9Xv7Tb3Nc6Hy1Qs5Ad'></div>" },
        Case { positive: false, kind: ContentKind::JavaScript, input: "const label = 'AKIAIOSFODNN7EXAMPLE';" },
    ];
    report(
        "secrets",
        measure(&SecretExtractor::with_random_key(), &secrets, |f| {
            f.kind == FindingKind::Secret
        }),
    );

    let dom = [
        Case {
            positive: true,
            kind: ContentKind::JavaScript,
            input: "target.innerHTML = location.hash;",
        },
        Case {
            positive: true,
            kind: ContentKind::JavaScript,
            input: "document.write(document.cookie);",
        },
        Case {
            positive: false,
            kind: ContentKind::JavaScript,
            input: "target.innerHTML = DOMPurify.sanitize(location.hash);",
        },
        Case {
            positive: false,
            kind: ContentKind::JavaScript,
            input: "target.innerHTML = trustedTemplate;",
        },
    ];
    report(
        "dom_xss_flows",
        measure(&DomSinkExtractor::new(), &dom, |f| {
            f.value.starts_with("DOM XSS:")
        }),
    );
}
