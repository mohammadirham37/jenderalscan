export namespace main {
	
	export class ExportPayload {
	    filename: string;
	    mimeType: string;
	    contentBase64: string;
	    savedPath: string;
	
	    static createFrom(source: any = {}) {
	        return new ExportPayload(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filename = source["filename"];
	        this.mimeType = source["mimeType"];
	        this.contentBase64 = source["contentBase64"];
	        this.savedPath = source["savedPath"];
	    }
	}

}

export namespace models {
	
	export class AppSettings {
	    maxWorkers: number;
	    rateLimitRps: number;
	    timeoutSeconds: number;
	    maxRetries: number;
	    userAgent: string;
	    customHeaders: Record<string, string>;
	    proxyUrl: string;
	    verifyTls: boolean;
	    strictScopeLock: boolean;
	    language: string;
	    theme: string;
	
	    static createFrom(source: any = {}) {
	        return new AppSettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.maxWorkers = source["maxWorkers"];
	        this.rateLimitRps = source["rateLimitRps"];
	        this.timeoutSeconds = source["timeoutSeconds"];
	        this.maxRetries = source["maxRetries"];
	        this.userAgent = source["userAgent"];
	        this.customHeaders = source["customHeaders"];
	        this.proxyUrl = source["proxyUrl"];
	        this.verifyTls = source["verifyTls"];
	        this.strictScopeLock = source["strictScopeLock"];
	        this.language = source["language"];
	        this.theme = source["theme"];
	    }
	}
	export class AuditLogEntry {
	    id: number;
	    scanId: string;
	    // Go type: time
	    timestamp: any;
	    targetUrl: string;
	    normalizedHost: string;
	    profile: string;
	    modulesExecuted: string;
	    authorizedConfirm: boolean;
	    authorizationNote: string;
	    rateLimitRps: number;
	    status: string;
	    durationMs: number;
	    totalFindings: number;
	
	    static createFrom(source: any = {}) {
	        return new AuditLogEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.scanId = source["scanId"];
	        this.timestamp = this.convertValues(source["timestamp"], null);
	        this.targetUrl = source["targetUrl"];
	        this.normalizedHost = source["normalizedHost"];
	        this.profile = source["profile"];
	        this.modulesExecuted = source["modulesExecuted"];
	        this.authorizedConfirm = source["authorizedConfirm"];
	        this.authorizationNote = source["authorizationNote"];
	        this.rateLimitRps = source["rateLimitRps"];
	        this.status = source["status"];
	        this.durationMs = source["durationMs"];
	        this.totalFindings = source["totalFindings"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class CVEDatasetMeta {
	    version: string;
	    // Go type: time
	    lastUpdated: any;
	    totalEntries: number;
	    source: string;
	
	    static createFrom(source: any = {}) {
	        return new CVEDatasetMeta(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.lastUpdated = this.convertValues(source["lastUpdated"], null);
	        this.totalEntries = source["totalEntries"];
	        this.source = source["source"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DetectedTech {
	    name: string;
	    category: string;
	    language?: string;
	    version: string;
	    confidence: string;
	    source: string;
	    cpe?: string;
	    tags?: string[];
	    potentialCves?: string[];
	
	    static createFrom(source: any = {}) {
	        return new DetectedTech(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.category = source["category"];
	        this.language = source["language"];
	        this.version = source["version"];
	        this.confidence = source["confidence"];
	        this.source = source["source"];
	        this.cpe = source["cpe"];
	        this.tags = source["tags"];
	        this.potentialCves = source["potentialCves"];
	    }
	}
	export class Finding {
	    id: string;
	    scanId: string;
	    module: string;
	    ruleId: string;
	    fingerprint: string;
	    title: string;
	    titleEn?: string;
	    severity: string;
	    confidence: string;
	    description: string;
	    descriptionEn: string;
	    impact: string;
	    impactEn: string;
	    recommendation: string;
	    recommendationEn: string;
	    evidence: string;
	    targetUrl: string;
	    references: string[];
	    cwe?: string;
	    owasp?: string;
	    cvss?: number;
	    diffStatus?: string;
	    // Go type: time
	    createdAt: any;
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.scanId = source["scanId"];
	        this.module = source["module"];
	        this.ruleId = source["ruleId"];
	        this.fingerprint = source["fingerprint"];
	        this.title = source["title"];
	        this.titleEn = source["titleEn"];
	        this.severity = source["severity"];
	        this.confidence = source["confidence"];
	        this.description = source["description"];
	        this.descriptionEn = source["descriptionEn"];
	        this.impact = source["impact"];
	        this.impactEn = source["impactEn"];
	        this.recommendation = source["recommendation"];
	        this.recommendationEn = source["recommendationEn"];
	        this.evidence = source["evidence"];
	        this.targetUrl = source["targetUrl"];
	        this.references = source["references"];
	        this.cwe = source["cwe"];
	        this.owasp = source["owasp"];
	        this.cvss = source["cvss"];
	        this.diffStatus = source["diffStatus"];
	        this.createdAt = this.convertValues(source["createdAt"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ModuleInfo {
	    id: string;
	    name: string;
	    nameEn: string;
	    description: string;
	    descriptionEn: string;
	    typicalSeverity: string;
	    phase: string;
	    defaultQuick: boolean;
	    defaultFull: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ModuleInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.nameEn = source["nameEn"];
	        this.description = source["description"];
	        this.descriptionEn = source["descriptionEn"];
	        this.typicalSeverity = source["typicalSeverity"];
	        this.phase = source["phase"];
	        this.defaultQuick = source["defaultQuick"];
	        this.defaultFull = source["defaultFull"];
	    }
	}
	export class ModuleStatus {
	    module: string;
	    name: string;
	    status: string;
	    findings: number;
	    durationMs: number;
	    errorMessage?: string;
	    // Go type: time
	    startedAt?: any;
	    // Go type: time
	    completedAt?: any;
	
	    static createFrom(source: any = {}) {
	        return new ModuleStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.module = source["module"];
	        this.name = source["name"];
	        this.status = source["status"];
	        this.findings = source["findings"];
	        this.durationMs = source["durationMs"];
	        this.errorMessage = source["errorMessage"];
	        this.startedAt = this.convertValues(source["startedAt"], null);
	        this.completedAt = this.convertValues(source["completedAt"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ScanDiff {
	    previousScanId?: string;
	    // Go type: time
	    previousDate?: any;
	    newCount: number;
	    recurringCount: number;
	    fixedCount: number;
	    fixedFindings?: Finding[];
	
	    static createFrom(source: any = {}) {
	        return new ScanDiff(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.previousScanId = source["previousScanId"];
	        this.previousDate = this.convertValues(source["previousDate"], null);
	        this.newCount = source["newCount"];
	        this.recurringCount = source["recurringCount"];
	        this.fixedCount = source["fixedCount"];
	        this.fixedFindings = this.convertValues(source["fixedFindings"], Finding);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SeveritySummary {
	    high: number;
	    medium: number;
	    low: number;
	    info: number;
	    total: number;
	
	    static createFrom(source: any = {}) {
	        return new SeveritySummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.high = source["high"];
	        this.medium = source["medium"];
	        this.low = source["low"];
	        this.info = source["info"];
	        this.total = source["total"];
	    }
	}
	export class ScanProgressEvent {
	    scanId: string;
	    targetUrl: string;
	    status: string;
	    progressPct: number;
	    elapsedMs: number;
	    requestsSent: number;
	    moduleStatuses: ModuleStatus[];
	    summary: SeveritySummary;
	    latestFinding?: Finding;
	
	    static createFrom(source: any = {}) {
	        return new ScanProgressEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.scanId = source["scanId"];
	        this.targetUrl = source["targetUrl"];
	        this.status = source["status"];
	        this.progressPct = source["progressPct"];
	        this.elapsedMs = source["elapsedMs"];
	        this.requestsSent = source["requestsSent"];
	        this.moduleStatuses = this.convertValues(source["moduleStatuses"], ModuleStatus);
	        this.summary = this.convertValues(source["summary"], SeveritySummary);
	        this.latestFinding = this.convertValues(source["latestFinding"], Finding);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ScanRequest {
	    targetUrl: string;
	    profile: string;
	    modules: string[];
	    authorizedConfirm: boolean;
	    authorizationNote: string;
	
	    static createFrom(source: any = {}) {
	        return new ScanRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.targetUrl = source["targetUrl"];
	        this.profile = source["profile"];
	        this.modules = source["modules"];
	        this.authorizedConfirm = source["authorizedConfirm"];
	        this.authorizationNote = source["authorizationNote"];
	    }
	}
	export class ScanResult {
	    id: string;
	    targetUrl: string;
	    normalizedHost: string;
	    profile: string;
	    status: string;
	    authorizedConfirm: boolean;
	    authorizationNote: string;
	    scopeLocked: boolean;
	    // Go type: time
	    startedAt: any;
	    // Go type: time
	    completedAt: any;
	    durationMs: number;
	    moduleStatuses: ModuleStatus[];
	    findings: Finding[];
	    technologies: DetectedTech[];
	    summary: SeveritySummary;
	    diff?: ScanDiff;
	    requestsSent: number;
	    errorMessage?: string;
	
	    static createFrom(source: any = {}) {
	        return new ScanResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.targetUrl = source["targetUrl"];
	        this.normalizedHost = source["normalizedHost"];
	        this.profile = source["profile"];
	        this.status = source["status"];
	        this.authorizedConfirm = source["authorizedConfirm"];
	        this.authorizationNote = source["authorizationNote"];
	        this.scopeLocked = source["scopeLocked"];
	        this.startedAt = this.convertValues(source["startedAt"], null);
	        this.completedAt = this.convertValues(source["completedAt"], null);
	        this.durationMs = source["durationMs"];
	        this.moduleStatuses = this.convertValues(source["moduleStatuses"], ModuleStatus);
	        this.findings = this.convertValues(source["findings"], Finding);
	        this.technologies = this.convertValues(source["technologies"], DetectedTech);
	        this.summary = this.convertValues(source["summary"], SeveritySummary);
	        this.diff = this.convertValues(source["diff"], ScanDiff);
	        this.requestsSent = source["requestsSent"];
	        this.errorMessage = source["errorMessage"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

