import React, { useEffect } from 'react';
import { View, Text, Button } from 'react-native';
import Luciq, {
  InvocationEvent,
  BugReporting,
  CrashReporting,
  SessionReplay,
  Surveys,
} from '@luciq/react-native';

const App = () => {
  useEffect(() => {
    initLuciq();
  }, []);

  const initLuciq = async () => {
    await Luciq.init({
      token: 'rn-app-token-67890',
      invocationEvents: [
        InvocationEvent.shake,
        InvocationEvent.screenshot,
        InvocationEvent.floatingButton,
      ],
      debugLogsLevel: 'verbose',
    });

    // Module configuration
    BugReporting.setEnabled(true);
    CrashReporting.setEnabled(true);
    SessionReplay.setEnabled(true);
    SessionReplay.setNetworkLogsEnabled(true);
    Surveys.setEnabled(true);

    // User identification
    Luciq.identifyUser('user@example.com', 'Jane Doe', 'user-456');

    // Custom logging
    Luciq.log('React Native app initialized');
    Luciq.setUserAttribute('platform', 'ios');
    Luciq.setCustomData('build_number', '123');

    // Feature flags
    Luciq.addFeatureFlags([
      { name: 'NewHomeScreen', variant: 'enabled' },
      { name: 'BetaFeature', variant: 'test_group_a' },
    ]);

    // Network logging configuration
    SessionReplay.setRequestFilterExpression('url.includes("api.example.com")');
  };

  const handleLogout = () => {
    Luciq.removeAllFeatureFlags();
    Luciq.logOut();
  };

  const showBugReporter = () => {
    Luciq.show();
  };

  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      <Text>React Native + Luciq</Text>
      <Button title="Report Bug" onPress={showBugReporter} />
      <Button title="Logout" onPress={handleLogout} />
    </View>
  );
};

export default App;
