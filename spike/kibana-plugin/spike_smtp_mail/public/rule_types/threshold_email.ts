import { lazy } from 'react';
import type {
  RuleTypeModel,
  ValidationResult,
} from '@kbn/triggers-actions-ui-plugin/public';
import { RULE_TYPE_ID } from '../../common';
import type { ThresholdEmailRuleParams } from './threshold_email_form';

export function getThresholdEmailRuleType(): RuleTypeModel<ThresholdEmailRuleParams> {
  return {
    id: RULE_TYPE_ID,
    description: 'Send an email over SMTP when a condition is met (Basic license, no Connectors).',
    iconClass: 'email',
    documentationUrl: null,
    // false → creatable in Stack Management → Rules (not only inside our own app)
    requiresAppContext: false,
    ruleParamsExpression: lazy(() => import('./threshold_email_form')),
    validate: (ruleParams: ThresholdEmailRuleParams): ValidationResult => {
      const errors: ValidationResult['errors'] = {
        to: [],
        subject: [],
      };
      if (!ruleParams.to || !String(ruleParams.to).trim()) {
        (errors.to as string[]).push('A recipient is required.');
      }
      if (!ruleParams.subject || !String(ruleParams.subject).trim()) {
        (errors.subject as string[]).push('A subject is required.');
      }
      if (
        ruleParams.minDocCount !== undefined &&
        (Number.isNaN(ruleParams.minDocCount) || ruleParams.minDocCount < 0)
      ) {
        errors.minDocCount = ['minDocCount must be ≥ 0'];
      }
      return { errors };
    },
    defaultActionMessage: 'SMTP mail rule "{{rule.name}}" fired (subject: {{context.subject}}).',
  };
}
