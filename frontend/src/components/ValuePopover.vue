<script setup>
import { computed } from 'vue'
import { ElMessage } from 'element-plus'
import { CopyDocument } from '@element-plus/icons-vue'

const props = defineProps({
  label: {
    type: String,
    required: true,
  },
  value: {
    type: [String, Number, Boolean],
    default: '',
  },
  emptyText: {
    type: String,
    default: '-',
  },
  placement: {
    type: String,
    default: 'top',
  },
  width: {
    type: [String, Number],
    default: 520,
  },
  popperClass: {
    type: String,
    default: '',
  },
})

const displayValue = computed(() => {
  if (props.value === null || props.value === undefined || props.value === '') {
    return props.emptyText
  }
  return String(props.value)
})

const hasValue = computed(() => displayValue.value !== props.emptyText)

const mergedPopperClass = computed(() => {
  return ['value-popover', props.popperClass].filter(Boolean).join(' ')
})

async function copyValue() {
  if (!hasValue.value) return

  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(displayValue.value)
    } else {
      const textarea = document.createElement('textarea')
      textarea.value = displayValue.value
      textarea.setAttribute('readonly', '')
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
    }
    ElMessage.success(`${props.label}已复制`)
  } catch (error) {
    ElMessage.error(`${props.label}复制失败`)
  }
}
</script>

<template>
  <el-popover
    trigger="click"
    :placement="placement"
    :width="width"
    :disabled="!hasValue"
    :popper-class="mergedPopperClass"
  >
    <template #reference>
      <slot name="reference" :label="label" :value="value" :display-value="displayValue">
        <code class="value-popover-reference" :class="{ disabled: !hasValue }">{{ displayValue }}</code>
      </slot>
    </template>

    <div class="value-popover-panel">
      <div class="value-popover-header">
        <div class="value-popover-title">{{ label }}</div>
        <el-tooltip :content="`复制${label}`" placement="top" popper-class="theme-tooltip">
          <el-button
            class="value-popover-copy"
            size="small"
            text
            :icon="CopyDocument"
            @click="copyValue"
          />
        </el-tooltip>
      </div>
      <pre class="value-popover-content"><code>{{ displayValue }}</code></pre>
    </div>
  </el-popover>
</template>

<style scoped>
.value-popover-reference {
  display: block;
  min-width: 0;
  padding: 6px 8px;
  overflow: hidden;
  border: 1px solid #32475b;
  border-radius: 5px;
  background: #1f2f3f;
  color: #e8eef5;
  cursor: pointer;
  font-family: Consolas, 'Courier New', monospace;
  font-size: 12px;
  font-weight: 500;
  line-height: 1.5;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.value-popover-reference.disabled {
  cursor: default;
}

:global(.value-popover) {
  max-width: min(720px, calc(100vw - 48px));
  border: 1px solid #32475b !important;
  background: #1f2f3f !important;
  color: #e8eef5 !important;
}

:global(.value-popover .el-popper__arrow::before) {
  border-color: #32475b !important;
  background: #1f2f3f !important;
}

:global(.value-popover-panel) {
  min-width: 0;
}

:global(.value-popover-header) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}

:global(.value-popover-title) {
  min-width: 0;
  color: #ffffff;
  font-size: 13px;
  font-weight: 700;
  line-height: 1.4;
}

:global(.value-popover-copy) {
  width: 24px;
  height: 24px;
  padding: 0;
  color: #9bd0ff;
  --el-button-hover-bg-color: #243447;
  --el-button-active-bg-color: #243447;
  --el-button-hover-text-color: #ffffff;
  --el-button-active-text-color: #ffffff;
}

:global(.value-popover-content) {
  max-height: 360px;
  margin: 0;
  padding: 10px 12px;
  overflow: auto;
  border: 1px solid #32475b;
  border-radius: 5px;
  background: #172331;
  color: #e8eef5;
  font-family: Consolas, 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.5;
  scrollbar-color: #4f6680 #1f2f3f;
  scrollbar-width: thin;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  word-break: break-word;
}

:global(.value-popover-content::-webkit-scrollbar) {
  width: 8px;
}

:global(.value-popover-content::-webkit-scrollbar-track) {
  background: #1f2f3f;
  border-radius: 999px;
}

:global(.value-popover-content::-webkit-scrollbar-thumb) {
  background: #4f6680;
  border-radius: 999px;
}

:global(.value-popover-content::-webkit-scrollbar-thumb:hover) {
  background: #66809b;
}
</style>
