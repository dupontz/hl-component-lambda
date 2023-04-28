CfhighlanderTemplate do
  Name 'lambda'
  ComponentVersion component_version
  Description "#{component_name} - #{component_version}"

  functions.each do |function_name, lambda_config|
    if (lambda_config.has_key? 'enable_eni') && (lambda_config['enable_eni'])
      DependsOn 'vpc'
      break
    end
  end if defined? functions

  DependsOn 'lib-iam'
  DependsOn 'lib-alb'



  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', isGlobal: true, allowedValues: ['development', 'production']
    ComponentParam 'UserPoolId', ''
    ComponentParam 'UserPoolClientId', ''
    ComponentParam 'UserPoolDomainName', ''

    if defined? targetgroup
      ComponentParam 'DnsDomain'
      if targetgroup.is_a?(Array)
        targetgroup.each do |tg|
          if tg.has_key?('rules')
            ComponentParam "#{tg['listener']}Listener"
          else
            ComponentParam "#{tg['name'].gsub(/[^0-9A-Za-z]/, '')}TargetGroup"
          end
        end
      else
        ComponentParam 'TargetGroup'
        ComponentParam 'Listener'
        ComponentParam 'LoadBalancer'
      end
    end

    functions.each do |function_name, lambda_config|
      if (lambda_config.has_key? 'enable_eni') && (lambda_config['enable_eni'])
        ComponentParam 'VPCId', type: 'AWS::EC2::VPC::Id'
        maximum_availability_zones.times do |az|
          ComponentParam "SubnetCompute#{az}"
        end
        break
      end
    end if defined? functions

  end

end
