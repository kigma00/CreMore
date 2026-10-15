{{- define "cremore.fullname" -}}
{{- printf "%s-cremore" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cremore.dnsEgress" -}}
- to:
    - namespaceSelector:
        matchLabels: {{ toYaml .Values.networkPolicy.dnsNamespaceSelector | nindent 10 }}
      podSelector:
        matchLabels: {{ toYaml .Values.networkPolicy.dnsPodSelector | nindent 10 }}
  ports: [{ protocol: UDP, port: 53 }, { protocol: TCP, port: 53 }]
{{- end -}}

{{- define "cremore.httpsEgress" -}}
{{- /*
  Outbound HTTPS is how a stolen scanner credential leaves the cluster, so this
  is the one control that limits exfiltration regardless of which credential is
  taken. httpsEgressCIDRs narrows it to the provider ranges actually in use;
  httpsCIDR remains the single-range form for existing values files.

  NetworkPolicy matches addresses, not names, so this cannot be a hostname
  allowlist. Restricting by provider hostname needs an egress proxy or a CNI
  with FQDN policy support; see docs/ARCHITECTURE.md (trust boundaries).
*/ -}}
{{- if .Values.networkPolicy.httpsEgressCIDRs }}
- to:
{{- range .Values.networkPolicy.httpsEgressCIDRs }}
    - ipBlock: { cidr: {{ . | quote }} }
{{- end }}
  ports: [{ protocol: TCP, port: 443 }]
{{- else }}
- to: [{ ipBlock: { cidr: {{ .Values.networkPolicy.httpsCIDR | quote }} } }]
  ports: [{ protocol: TCP, port: 443 }]
{{- end }}
{{- end -}}

{{- define "cremore.backendEgress" -}}
{{ include "cremore.dnsEgress" . }}
- to: [{ ipBlock: { cidr: {{ .Values.networkPolicy.databaseCIDR | quote }} } }]
  ports: [{ protocol: TCP, port: {{ .Values.networkPolicy.databasePort | int }} }]
{{ include "cremore.httpsEgress" . }}
{{- if .Values.networkPolicy.eksPodIdentity }}
- to: [{ ipBlock: { cidr: "169.254.170.23/32" } }]
  ports: [{ protocol: TCP, port: 80 }]
- to: [{ ipBlock: { cidr: "fd00:ec2::23/128" } }]
  ports: [{ protocol: TCP, port: 80 }]
{{- end }}
{{- end -}}

{{- define "cremore.isolatedEgress" -}}
{{ include "cremore.dnsEgress" .root }}
{{- if ne .component "web" }}
- to: [{ ipBlock: { cidr: {{ .root.Values.networkPolicy.databaseCIDR | quote }} } }]
  ports: [{ protocol: TCP, port: {{ .root.Values.networkPolicy.databasePort | int }} }]
{{- end }}
{{- range index .root.Values.isolation.egress .component }}
- to: [{ ipBlock: { cidr: {{ .cidr | quote }} } }]
  ports: [{ protocol: TCP, port: {{ .port | int }} }]
{{- end }}
{{- end -}}

{{- define "cremore.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cremore.fullname" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "cremore.labels" -}}
{{ include "cremore.selectorLabels" . }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
{{- end -}}

{{- define "cremore.serviceAccountName" -}}
{{- $account := index .root.Values.serviceAccounts .component -}}
{{- if $account.name -}}
{{- $account.name -}}
{{- else -}}
{{- printf "%s-%s" (include "cremore.fullname" .root) .component -}}
{{- end -}}
{{- end -}}
