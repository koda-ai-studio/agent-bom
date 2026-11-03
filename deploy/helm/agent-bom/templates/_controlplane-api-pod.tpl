{{/*
Shared control-plane API process Deployment.

The API and the optional scan/ingest worker run the same image, arguments,
Postgres identities, secrets, service account and security contract; only the
role, replica count, scheduling and resources differ. Rendering both from one
definition keeps the two pods from drifting.

Call with (dict "root" $ "component" "api"|"worker").
*/}}
{{- define "agent-bom.controlPlaneApiValidate" -}}
{{- $cp := .Values.controlPlane -}}
{{- $postgresSecrets := $cp.postgresSecrets -}}
{{- $worker := $cp.worker | default dict -}}
{{- $autoCorrelationMaxAge := int $cp.autoCorrelation.maxAgeHours -}}
{{- if or (lt $autoCorrelationMaxAge 1) (gt $autoCorrelationMaxAge 8760) -}}
{{- fail "controlPlane.autoCorrelation.maxAgeHours must be between 1 and 8760" -}}
{{- end -}}
{{- $roleEnv := list "AGENT_BOM_API_ROLE" "AGENT_BOM_DISTRIBUTED_SCANS" -}}
{{- range $entry := $cp.api.env -}}
{{- if eq (get $entry "name") "AGENT_BOM_CONTROL_PLANE_REPLICAS" -}}
{{- fail "controlPlane.api.env cannot override AGENT_BOM_CONTROL_PLANE_REPLICAS; use replicas and autoscaling settings" -}}
{{- end -}}
{{- if has (get $entry "name") (list "AGENT_BOM_GRAPH_AUTO_CORRELATE" "AGENT_BOM_GRAPH_AUTO_CORRELATE_MAX_AGE_HOURS") -}}
{{- fail "controlPlane.api.env cannot override automatic correlation variables; use controlPlane.autoCorrelation" -}}
{{- end -}}
{{- if and $worker.enabled (has (get $entry "name") $roleEnv) -}}
{{- fail (printf "controlPlane.api.env cannot set %s when controlPlane.worker.enabled=true; the chart assigns process roles" (get $entry "name")) -}}
{{- end -}}
{{- end -}}
{{- if $worker.enabled -}}
{{- if not $postgresSecrets.enabled -}}
{{- fail "controlPlane.worker.enabled requires controlPlane.postgresSecrets.enabled=true: workers drain the shared Postgres scan_dispatch_queue" -}}
{{- end -}}
{{- range $entry := $worker.extraEnv -}}
{{- if has (get $entry "name") (concat $roleEnv (list "AGENT_BOM_CONTROL_PLANE_REPLICAS" "AGENT_BOM_GRAPH_AUTO_CORRELATE" "AGENT_BOM_GRAPH_AUTO_CORRELATE_MAX_AGE_HOURS" "AGENT_BOM_POSTGRES_URL" "AGENT_BOM_POSTGRES_MAINTENANCE_URL" "AGENT_BOM_POSTGRES_PROVIDER" "ALEMBIC_DATABASE_URL")) -}}
{{- fail (printf "controlPlane.worker.extraEnv cannot set %s; it is chart-managed" (get $entry "name")) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $postgresSecrets.enabled -}}
{{- $appSecret := required "controlPlane.postgresSecrets.appSecretRef.name is required" $postgresSecrets.appSecretRef.name -}}
{{- $maintenanceSecret := required "controlPlane.postgresSecrets.maintenanceSecretRef.name is required" $postgresSecrets.maintenanceSecretRef.name -}}
{{- $adminSecret := required "controlPlane.postgresSecrets.adminSecretRef.name is required" $postgresSecrets.adminSecretRef.name -}}
{{- if ne (len (uniq (list $appSecret $maintenanceSecret $adminSecret))) 3 -}}
{{- fail "controlPlane.postgresSecrets app, maintenance, and admin Secret names must be distinct" -}}
{{- end -}}
{{- range $entry := $cp.api.env -}}
{{- if has (get $entry "name") (list "AGENT_BOM_POSTGRES_URL" "AGENT_BOM_POSTGRES_MAINTENANCE_URL" "AGENT_BOM_POSTGRES_PROVIDER" "ALEMBIC_DATABASE_URL") -}}
{{- fail "controlPlane.api.env cannot override canonical Postgres identity variables when controlPlane.postgresSecrets.enabled=true" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Every API-image process sharing the control-plane database: API capacity plus
worker capacity when the worker split is on. Feeds the shared-state guards.
*/}}
{{- define "agent-bom.controlPlaneProcessCapacity" -}}
{{- $capacity := int (include "agent-bom.controlPlaneReplicaCapacity" .Values.controlPlane.api) -}}
{{- $worker := .Values.controlPlane.worker | default dict -}}
{{- if $worker.enabled -}}
{{- $capacity = add $capacity (int (include "agent-bom.controlPlaneReplicaCapacity" $worker)) -}}
{{- end -}}
{{- $capacity -}}
{{- end -}}

{{- define "agent-bom.controlPlaneApiDeployment" -}}
{{- $root := .root -}}
{{- $component := .component -}}
{{- $cp := $root.Values.controlPlane -}}
{{- $api := $cp.api -}}
{{- $worker := $cp.worker | default dict -}}
{{- $isWorker := eq $component "worker" -}}
{{- $workload := ternary $worker $api $isWorker -}}
{{- $postgresSecrets := $cp.postgresSecrets -}}
{{- $nodeSelector := $root.Values.nodeSelector -}}
{{- $tolerations := $root.Values.tolerations -}}
{{- if $isWorker -}}
{{- $nodeSelector = $worker.nodeSelector | default $root.Values.nodeSelector -}}
{{- $tolerations = $worker.tolerations | default $root.Values.tolerations -}}
{{- end -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "agent-bom.name" $root }}-{{ $component }}
  namespace: {{ $root.Release.Namespace }}
  labels:
    {{- include "agent-bom.labels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ $component }}
spec:
  replicas: {{ $workload.replicas }}
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ include "agent-bom.name" $root }}
      app.kubernetes.io/component: {{ $component }}
  template:
    metadata:
      labels:
        {{- include "agent-bom.labels" $root | nindent 8 }}
        app.kubernetes.io/component: {{ $component }}
      {{- with $root.Values.podAnnotations }}
      annotations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
    spec:
      {{- if $api.serviceAccount.create }}
      serviceAccountName: {{ include "agent-bom.controlPlaneApiServiceAccountName" $root }}
      automountServiceAccountToken: {{ $api.serviceAccount.automountServiceAccountToken }}
      {{- else }}
      automountServiceAccountToken: false
      {{- end }}
      terminationGracePeriodSeconds: {{ $workload.terminationGracePeriodSeconds | default $api.terminationGracePeriodSeconds | default 30 }}
      {{- $priorityClassName := include "agent-bom.controlPlanePriorityClassName" $root }}
      {{- if $priorityClassName }}
      priorityClassName: {{ $priorityClassName }}
      {{- end }}
      {{- with $root.Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      securityContext:
        {{- toYaml $root.Values.podSecurityContext | nindent 8 }}
      {{- include "agent-bom.controlPlaneTopologySpreadConstraints" (dict "Values" $root.Values "component" $component "Chart" $root.Chart "Release" $root.Release) | nindent 6 }}
      {{- if and $isWorker $worker.affinity }}
      affinity:
        {{- toYaml $worker.affinity | nindent 8 }}
      {{- else }}
      {{- include "agent-bom.controlPlaneAffinity" (dict "Values" $root.Values "component" $component "Chart" $root.Chart "Release" $root.Release) | nindent 6 }}
      {{- end }}
      containers:
        - name: {{ $component }}
          image: "{{ $root.Values.image.repository }}:{{ $root.Values.image.tag }}"
          imagePullPolicy: {{ $root.Values.image.pullPolicy }}
          args:
            {{- range $api.args }}
            - {{ . | quote }}
            {{- end }}
          ports:
            - containerPort: {{ $api.port }}
              name: http
              protocol: TCP
          env:
            - name: AGENT_BOM_CONTROL_PLANE_REPLICAS
              value: {{ include "agent-bom.controlPlaneProcessCapacity" $root | quote }}
            {{- if $worker.enabled }}
            - name: AGENT_BOM_API_ROLE
              value: {{ $component | quote }}
            - name: AGENT_BOM_DISTRIBUTED_SCANS
              value: "1"
            {{- end }}
            {{- if $cp.connectionsScheduler.enabled }}
            - name: AGENT_BOM_CONNECTIONS_SCHEDULER
              value: "1"
            {{- with $cp.connectionsScheduler.maxConcurrency }}
            - name: AGENT_BOM_CONNECTIONS_SCHEDULER_MAX_CONCURRENCY
              value: {{ . | quote }}
            {{- end }}
            {{- with $cp.connectionsScheduler.pollSeconds }}
            - name: AGENT_BOM_CONNECTIONS_SCHEDULER_POLL_SECONDS
              value: {{ . | quote }}
            {{- end }}
            {{- end }}
            - name: AGENT_BOM_GRAPH_AUTO_CORRELATE
              value: {{ $cp.autoCorrelation.enabled | quote }}
            - name: AGENT_BOM_GRAPH_AUTO_CORRELATE_MAX_AGE_HOURS
              value: {{ $cp.autoCorrelation.maxAgeHours | quote }}
            {{- include "agent-bom.nvdApiKeyEnv" $root | nindent 12 }}
          {{- with $api.env }}
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- if $isWorker }}
          {{- with $worker.extraEnv }}
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- end }}
            {{- if $postgresSecrets.enabled }}
            - name: AGENT_BOM_POSTGRES_PROVIDER
              value: {{ $cp.postgres.provider | quote }}
            - name: AGENT_BOM_POSTGRES_URL
              valueFrom:
                secretKeyRef:
                  name: {{ $postgresSecrets.appSecretRef.name | quote }}
                  key: AGENT_BOM_POSTGRES_URL
            - name: AGENT_BOM_POSTGRES_MAINTENANCE_URL
              valueFrom:
                secretKeyRef:
                  name: {{ $postgresSecrets.maintenanceSecretRef.name | quote }}
                  key: AGENT_BOM_POSTGRES_MAINTENANCE_URL
            {{- end }}
          {{- with $api.envFrom }}
          envFrom:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          securityContext:
            {{- toYaml $root.Values.securityContext | nindent 12 }}
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            {{- with $api.extraVolumeMounts }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          resources:
            {{- toYaml ($workload.resources | default $api.resources) | nindent 12 }}
          livenessProbe:
            {{- toYaml $api.livenessProbe | nindent 12 }}
          readinessProbe:
            {{- toYaml $api.readinessProbe | nindent 12 }}
          startupProbe:
            {{- toYaml $api.startupProbe | nindent 12 }}
      {{- with $nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      volumes:
        - name: tmp
          emptyDir: {}
        {{- with $api.extraVolumes }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
{{- end }}
