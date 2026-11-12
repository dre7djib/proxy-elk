import React, { useEffect } from 'react';
import { EuiFormRow, EuiFieldText, EuiFieldNumber, EuiTextArea, EuiSpacer } from '@elastic/eui';
import type { RuleTypeParamsExpressionProps } from '@kbn/triggers-actions-ui-plugin/public';

export interface ThresholdEmailRuleParams {
  to?: string;
  subject?: string;
  body?: string;
  index?: string;
  minDocCount?: number;
  query?: string;
}

const ThresholdEmailForm: React.FunctionComponent<
  RuleTypeParamsExpressionProps<ThresholdEmailRuleParams>
> = ({ ruleParams, setRuleParams, errors }) => {
  // Defaults so the create flyout is valid after first paint
  useEffect(() => {
    if (ruleParams.body === undefined) {
      setRuleParams('body', 'Alert fired.');
    }
    if (ruleParams.minDocCount === undefined) {
      setRuleParams('minDocCount', 1);
    }
    if (ruleParams.query === undefined) {
      setRuleParams('query', '*');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fieldError = (key: keyof ThresholdEmailRuleParams): string | undefined => {
    const err = errors?.[key as string];
    if (Array.isArray(err)) {
      return err[0];
    }
    return typeof err === 'string' ? err : undefined;
  };

  return (
    <>
      <EuiFormRow
        label="To"
        helpText="Comma-separated addresses"
        isInvalid={Boolean(fieldError('to'))}
        error={fieldError('to')}
        fullWidth
      >
        <EuiFieldText
          fullWidth
          value={ruleParams.to ?? ''}
          onChange={(e) => setRuleParams('to', e.target.value)}
          placeholder="ops@example.com"
          data-test-subj="spikeSmtpMail-to"
        />
      </EuiFormRow>

      <EuiFormRow
        label="Subject"
        isInvalid={Boolean(fieldError('subject'))}
        error={fieldError('subject')}
        fullWidth
      >
        <EuiFieldText
          fullWidth
          value={ruleParams.subject ?? ''}
          onChange={(e) => setRuleParams('subject', e.target.value)}
          data-test-subj="spikeSmtpMail-subject"
        />
      </EuiFormRow>

      <EuiFormRow label="Body" fullWidth>
        <EuiTextArea
          fullWidth
          value={ruleParams.body ?? ''}
          onChange={(e) => setRuleParams('body', e.target.value)}
          data-test-subj="spikeSmtpMail-body"
        />
      </EuiFormRow>

      <EuiSpacer size="m" />

      <EuiFormRow
        label="Index (optional)"
        helpText="If set, mail is sent only when the hit count reaches the threshold"
        fullWidth
      >
        <EuiFieldText
          fullWidth
          value={ruleParams.index ?? ''}
          onChange={(e) => setRuleParams('index', e.target.value || undefined)}
          placeholder="logs-*"
          data-test-subj="spikeSmtpMail-index"
        />
      </EuiFormRow>

      <EuiFormRow label="Min document count" fullWidth>
        <EuiFieldNumber
          fullWidth
          min={0}
          value={ruleParams.minDocCount ?? 1}
          onChange={(e) => setRuleParams('minDocCount', e.target.valueAsNumber)}
          data-test-subj="spikeSmtpMail-minDocCount"
        />
      </EuiFormRow>

      <EuiFormRow label="Query string" fullWidth>
        <EuiFieldText
          fullWidth
          value={ruleParams.query ?? '*'}
          onChange={(e) => setRuleParams('query', e.target.value)}
          data-test-subj="spikeSmtpMail-query"
        />
      </EuiFormRow>
    </>
  );
};

// Default export for React.lazy()
// eslint-disable-next-line import/no-default-export
export default ThresholdEmailForm;
